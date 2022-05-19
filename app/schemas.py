import typing
from collections import namedtuple
from dataclasses import dataclass


@dataclass
class Message:
    plaintext: typing.Union[str, bytes]
    associated_data: typing.Union[str, bytes] = None

    @property
    def plaintext(self):
        return self._plaintext

    @plaintext.setter
    def plaintext(self, value):
        if isinstance(value, bytes):
            self._plaintext = value
        elif isinstance(value, str):
            self._plaintext = value.encode()
        else:
            raise TypeError("Plaintext must be str or bytes.")

    @property
    def associated_data(self):
        try:
            return self._associated_data
        except AttributeError:
            return None

    @associated_data.setter
    def associated_data(self, value):
        if isinstance(value, bytes):
            self._associated_data = value
        elif isinstance(value, str):
            self._associated_data = value.encode()
        else:
            return None


Token = namedtuple(
    "Token",
    [
        "timestamp",
        "iv",
        "ciphertext",
        "hmac",
    ],
)

TokenAssociatedData = namedtuple(
    "Token",
    [
        "associated_data",
        "timestamp",
        "iv",
        "ciphertext",
        "hmac",
    ],
)
