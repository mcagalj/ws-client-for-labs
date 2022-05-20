import json
import typing
from itertools import count

from .crypto import (
    AuthenticatedEncryption,
    InvalidToken,
    derive_key,
    derive_key_from_low_entropy,
)
from .schemas import Message
from .utils import base64_decode


class MessageProcessor:
    def __init__(
        self,
        secret: typing.Union[str, bytes, None] = None,
        username: str = None,
    ) -> None:
        self.username = username
        self.secret = secret
        self._N_out = 0
        self._N_in = 0

    def __str__(self):
        return f"Message processor for {self.username} ({id(self)})"

    @property
    def secret(self):
        raise AttributeError("The secret is write-only.")

    @secret.setter
    def secret(self, value: typing.Union[str, bytes, None]) -> None:
        if value is None:
            self._key = None
            self._aead = None
        elif isinstance(value, str):
            self._key = derive_key_from_low_entropy(
                length=96,
                key_seed=value,
                salt=self.username,
            )
            self._chain_key = self._key[:32]
            self._aead = AuthenticatedEncryption(self._key[32:])
        else:
            raise TypeError("The secret must be str or bytes.")

    def process_inbound(self, message: str) -> Message:
        counter = int.from_bytes(base64_decode(message.split(".")[0])[:8], "big")
        current_key = self._key
        current_N_in = self._N_in
        while self._N_in < counter:
            self._N_in += 1
            self._update_keys()
        try:
            message = self._aead.decrypt(token=message)
            message.associated_data = message.associated_data[8:]
            return message
        except InvalidToken:
            self._key = current_key
            self._N_in = current_N_in
            raise InvalidToken

    def process_outbound(self, message: Message) -> bytes:
        try:
            self._update_keys()
            message = self._update_message_counter(message)
            token = self._aead.encrypt(
                plaintext=message.plaintext,
                associated_data=message.associated_data,
            )
        except AttributeError:
            token = message

        return token

    def _update_keys(self) -> None:
        key = derive_key(
            length=96,
            key_seed=self._chain_key,
        )
        self._key = key
        self._chain_key = key[:32]
        self._aead.key = key[32:]

    def _update_message_counter(self, message: Message) -> Message:
        self._N_out += 1
        associated_data = self._N_out.to_bytes(8, "big")
        if message.associated_data is not None:
            associated_data += message.associated_data

        return Message(
            plaintext=message.plaintext,
            associated_data=associated_data,
        )
