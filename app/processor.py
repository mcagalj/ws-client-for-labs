import typing

from .crypto import AuthenticatedEncryption, derive_key_from_low_entropy


class MessageProcessor:
    def __init__(
        self, secret: typing.Union[str, bytes, None] = None, username: str = None
    ) -> None:
        self.username = username
        self.secret = secret

    def __str__(self):
        return f"Message processor for {self.username} ({id(self)})"

    @property
    def secret(self):
        raise AttributeError("The secret is write-only.")

    @secret.setter
    def secret(self, secret: typing.Union[str, bytes, None]) -> None:
        if secret is None:
            self._key = None
            self._aead = None
        elif isinstance(secret, str):
            self._key = derive_key_from_low_entropy(key_seed=secret, salt=self.username)
            self._aead = AuthenticatedEncryption(self._key)
        else:
            raise TypeError("The secret must be str.")

    def process_inbound(self, message: str) -> str:
        return self._aead.decrypt(token=message)

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
