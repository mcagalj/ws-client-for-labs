import typing

from .crypto import AuthenticatedEncryption, derive_key_from_low_entropy
from .schemas import Message


class MessageProcessor:
    def __init__(
        self,
        secret: typing.Union[str, bytes, None] = None,
        username: str = None,
    ) -> None:
        self.username = username
        self.secret = secret
        self.N_out = 0
        self.N_in = 0

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
                key_seed=value,
                salt=self.username,
            )
            self._aead = AuthenticatedEncryption(self._key)
        else:
            raise TypeError("The secret must be str.")

    def process_inbound(self, message: str) -> Message:
        return self._aead.decrypt(token=message)

    def process_outbound(self, message: Message) -> bytes:
        try:
            token = self._aead.encrypt(
                plaintext=message.plaintext,
                associated_data=message.associated_data,
            )
        except AttributeError:
            token = message

        return token

    def _update_secret(self):
        pass
