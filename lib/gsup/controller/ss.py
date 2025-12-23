"""
    PyHSS GSUP PurgeUE Controller
    Copyright (C) 2025  Lennart Rosam <hello@takuto.de>
    Copyright (C) 2025  Alexander Couzens <lynxis@fe80.eu>

    SPDX-License-Identifier: AGPL-3.0-or-later

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU Affero General Public License as published
    by the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Affero General Public License for more details.

    You should have received a copy of the GNU Affero General Public License
    along with this program.  If not, see <https://www.gnu.org/licenses/>.
"""

from osmocom.gsup.message import MsgType

from gsup.controller.abstract_controller import GsupController
from gsup.protocol.gsup_msg import GsupMessageUtil, GsupMessageBuilder
from gsup.codecs import GSM

import asn1tools
import gsm0338
import binascii
import pathlib

from collections import OrderedDict


class UnknownUSSD(RuntimeError):
    """ Unknown USSD message """ 
    pass

# FIXME: path
from importlib import resources as impresources
USSD = asn1tools.compile_files([impresources.files(__package__)/ 'ussd.asn'])

class SSController(GsupController):
    def __init__(self, logger, database):
        super().__init__(logger, database)

    @staticmethod
    def error_from_request(message: dict):
        """ Generate a SS Error by using the old message """
        response = GsupMessageBuilder().with_msg_type(MsgType.PROC_SS_RESULT)

        def copy_field(key: str):
            field = GsupMessageUtil.get_first_ie_by_name(key, message)
            if field:
                response.with_ie(key, field)

        copy_field('imsi')
        copy_field('session_id')

        return response.with_ie('session_state', 'end').build()

    @staticmethod
    def gsup_from_ussd(message: dict, ussd_encoded: bytes):
        """ Generate a full GSUP message """
        response = GsupMessageBuilder().with_msg_type(MsgType.PROC_SS_RESULT)

        def copy_field(key: str):
            field = GsupMessageUtil.get_first_ie_by_name(key, message)
            if field:
                response.with_ie(key, field)

        copy_field('imsi')
        copy_field('session_id')

        return response.with_ie('session_state', 'end').with_ie('supplementary_service_info', ussd_encoded).build()

    def get_msisdn(self, subscriber) -> str:
        return f"Your extension is {subscriber['msisdn']}"

    def get_imsi(self, subscriber) -> str:
        return f"Your IMSI is {subscriber['imsi']}"

    @staticmethod
    def encode_ussd_arg(answer: str) -> bytes:
        """
        Encode USSD-Arg of MAP into bytes
        
        OrderedDict([('ussd-DataCodingScheme', b'\x0f'),
             ('ussd-String', b'\xaaQ\x0c\x06\x1b\x01')])
        """
        attr = USSD.modules['Foo']['USSD-Arg']
        data = OrderedDict()
        data['ussd-DataCodingScheme'] = b'\x0f'
        data['ussd-String'] = binascii.a2b_hex(GSM().encode(answer))

        return attr.encode(data)
    
    @staticmethod
    def encode_component(invoke_id: int, answer: str):
        """
        Generate a full response which only needs to be encoded into GSUP
        FIXME: clean this up more

        The result should look like this:
            ('returnResultLast',
                OrderedDict(
                  ('invokeID', 1),
                  ('resultretres',
                        OrderedDict(('opCode', ('localValue', 59)),
                                ('returnparameter',
                                 bytearray(b'0\x1e\x04\x01\x0f\x04\x19\xd9w]\x0eJ'
                                           b'6\xa7IPz\x0e\x92\xd9d4\x99\xed'
                                           b'F\xbb\xe1f0\x99\xad\x06'))))))
        """
        comp = USSD.modules['Foo']['Component']
        outer = OrderedDict()
        outer['invokeID'] = invoke_id

        inner = OrderedDict()
        inner['opCode'] = ('localValue', 59)
        inner['returnparameter'] = SSController.encode_ussd_arg(answer)
        outer['resultretres'] = inner

        answer = comp.encode(('returnResultLast', outer))
        return answer

    async def handle_ussd(self, peer, message, subscriber, ussd_data):
        try:
            op, data = USSD.decode('Component', ussd_data)
            if op == "invoke":
                if data['opCode'] != ('localValue', 59):
                    raise UnknownUSSD(f"Invalid opCode in invoke {data}")

                invoke_id = data['invokeID']
                ussd = USSD.decode('USSD-Arg', data['invokeparameter'])
                target = GSM().decode(ussd['ussd-String'])
                await self._logger.logAsync(service='GSUP', level='INFO', message=f"Received USSD request {target}")

                # TODO: check called USSD code
                targets = {
                    '*#100#': self.get_msisdn,
                    '*#101#': self.get_imsi,
                }
                if target in targets:
                    answer = targets[target](subscriber)
                else:
                    answer = 'Your dialed USSD is invalid. We\'re very sorry.'

                component = self.encode_component(invoke_id, answer)
                response = self.gsup_from_ussd(message, component)
                await self._send_gsup_response(peer, response)
                return
            elif op == "returnResultLast":
                pass
            else:
                raise UnknownUSSD(f"Invalid class or constructed {op} with {data}")

            response = self.error_from_request(message)
            await self._send_gsup_response(peer, response)

        except Exception as e:
            await self._logger.logAsync(service='GSUP', level='ERROR', message=f"Error while handling ussd in handle_ussd: {str(e)}")
            raise UnknownUSSD("Invalid class or constructed")

    async def handle_message(self, peer, message):
        message = message.to_dict()
        imsi = GsupMessageUtil.get_first_ie_by_name('imsi', message)
        if imsi is None:
            await self._logger.logAsync(service='GSUP', level='WARN', message=f"IMSI not found in SS message from {peer}")
            response = self.error_from_request(message)
            await self._send_gsup_response(peer, response)
            return

        # Currently we only support non-continous sessions
        session_state = GsupMessageUtil.get_first_ie_by_name('session_state', message)
        if session_state is None:
            await self._logger.logAsync(service='GSUP', level='WARN', message=f"Session state not found in SS message from {peer}")
            response = self.error_from_request(message)
            await self._send_gsup_response(peer, response)
            return

        session_id = GsupMessageUtil.get_first_ie_by_name('session_id', message)
        if session_id is None:
            await self._logger.logAsync(service='GSUP', level='WARN', message=f"Session id not found in SS message from {peer}")
            response = self.error_from_request(message)
            await self._send_gsup_response(peer, response)
            return

        try:
            subscriber = self._database.Get_Subscriber(imsi=imsi)
            if subscriber is None:
                await self._logger.logAsync(service='GSUP', level='WARN', message=f"No subscriber for IMSI found. WTF?! {peer}")
                response = self.error_from_request(message)
                await self._send_gsup_response(peer, response)
                return

            ussd_data = GsupMessageUtil.get_first_ie_by_name('supplementary_service_info', message)
            await self.handle_ussd(peer, message, subscriber, ussd_data)

        except Exception as e:
            await self._logger.logAsync(service='GSUP', level='ERROR', message=f"Error while handling ussd: {str(e)}")
            response = self.error_from_request(message)
            await self._send_gsup_response(peer, response)
            return
