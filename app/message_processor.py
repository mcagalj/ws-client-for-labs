import typing

from app.crypto import (
    AuthenticatedEncryption,
    derive_key_from_high_entropy,
    derive_key_from_low_entropy,
)


class MessageProcessor:
    def __init__(self, shared_secret: typing.Union[str, bytes, None] = None) -> None:
        self.shared_secret = shared_secret

    @property
    def shared_secret(self):
        raise AttributeError("The shared_secret is write-only.")

    @shared_secret.setter
    def shared_secret(self, shared_secret: typing.Union[str, bytes, None]) -> None:
        if shared_secret is None:
            self._key = None
            self._aead = None
        elif isinstance(shared_secret, str):
            self._key = derive_key_from_low_entropy(shared_secret)
            self._aead = AuthenticatedEncryption(self._key)
        elif isinstance(shared_secret, bytes):
            self._key = derive_key_from_high_entropy(shared_secret)
            self._aead = AuthenticatedEncryption(self._key)
        else:
            raise TypeError("The shared_secred must be either str, bytes or None.")

    def process_inbound(self, message: str) -> str:
        pass

    def process_outbound(
        self,
        message: typing.Union[str, bytes],
        associated_data: typing.Union[str, bytes] = None,
    ) -> None:
        if isinstance(message, str):
            message = message.encode()

        if isinstance(associated_data, str):
            associated_data = associated_data.encode()

        try:
            token = self._aead.encrypt(
                plaintext=message, associated_data=associated_data
            )
        except AttributeError:
            token = message

        return token
