import typing

from .crypto import (
    AuthenticatedEncryption,
    InvalidToken,
    derive_key,
    derive_key_from_low_entropy,
)
from .schemas import Message
from .utils import base64_decode

CTR_SIZE_BYTES = 4


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
        self._N_out = 0
        self._N_in = 0

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
        counter = MessageProcessor._get_message_counter(message)

        print(f"INFO: received {counter} (local {self._N_in})")

        saved_key = self._key
        saved_counter = self._N_in

        self._skip_message_keys(until=counter)
        message = self._try_skipped_message_keys(
            message=message,
            saved_key=saved_key,
            saved_counter=saved_counter,
        )

        return message

    def process_outbound(self, message: Message) -> bytes:
        try:
            self._update_keys()
            message = self._set_message_counter(message)
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

    def _set_message_counter(self, message: Message) -> Message:
        self._N_out += 1
        associated_data = self._N_out.to_bytes(CTR_SIZE_BYTES, "big")
        if message.associated_data is not None:
            associated_data += message.associated_data

        return Message(
            plaintext=message.plaintext,
            associated_data=associated_data,
        )

    @staticmethod
    def _get_message_counter(token: str) -> int:
        return int.from_bytes(
            base64_decode(token.split(".")[0])[:CTR_SIZE_BYTES],
            "big",
        )

    def _skip_message_keys(self, until: int) -> None:
        while self._N_in < until:
            self._update_keys()
            self._N_in += 1

    def _try_skipped_message_keys(
        self,
        message: Message,
        saved_key: bytes,
        saved_counter: int,
    ) -> Message:
        try:
            message = self._aead.decrypt(token=message)
            message.associated_data = message.associated_data[CTR_SIZE_BYTES:]
            return message
        except InvalidToken:
            # Reset keys back to original values
            self._key = saved_key
            self._N_in = saved_counter
            self._chain_key = self._key[:32]
            self._aead.key = self._key[32:]
            raise InvalidToken
