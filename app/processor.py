import typing

from .schemas import Message


class MessageProcessor:
    def __init__(
        self,
        secret: typing.Union[str, bytes, None] = None,
        username: str = None,
    ) -> None:
        self.username = username
        self.secret = secret

    def __str__(self):
        return f"Message processor for {self.username} ({id(self)})"

    @property
    def secret(self):
        raise AttributeError("The secret is write-only.")

    @secret.setter
    def secret(self, value: typing.Union[str, bytes, None]) -> None:
        self._key = value

    def process_inbound(self, message: str) -> Message:
        return message

    def process_outbound(self, message: Message) -> bytes:
        return message
