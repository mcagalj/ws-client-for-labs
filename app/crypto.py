import base64
import os
import time
import typing

from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.hmac import HMAC
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

_KEY_SEED_LENGTH = 64
_AUTH_TAG_LENGTH = 16
_MAX_CLOCK_SKEW = 60
_TOKEN_DELIMITER = "."


def check_bytes(name: str, value: bytes) -> None:
    """
    Taken from https://cryptography.io
    """
    if not isinstance(value, bytes):
        raise TypeError(f"{name} must be bytes")


def base64_encode(input: bytes) -> str:
    """
    url-safe encodes and reemoves any `=` used as padding from the encoded input.
    https://gist.github.com/cameronmaske/f520903ade824e4c30ab
    """
    encoded = base64.urlsafe_b64encode(input).decode()
    return encoded.rstrip("=")


def base64_decode(input):
    """
    Adds back in the required padding before decoding.
    https://gist.github.com/cameronmaske/f520903ade824e4c30ab
    """
    padding = 4 - (len(input) % 4)
    input = input + ("=" * padding)
    return base64.urlsafe_b64decode(input)


def derive_key_from_low_entropy(key_seed: str) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=_KEY_SEED_LENGTH,
        salt=b"0" * 32,
        iterations=390000,
    )
    key = kdf.derive(key_seed.encode())
    return key


def derive_key_from_high_entropy(key_seed: bytes) -> bytes:
    kdf = HKDF(
        algorithm=hashes.SHA256(),
        length=_KEY_SEED_LENGTH,
        salt=b"0" * 32,
        info=b"high entropy seed",
    )
    key = kdf.derive(key_seed)
    return key


class AuthenticatedEncryption:
    """
    Heavily inspired by Fernet (https://cryptography.io).
    """

    def __init__(self, key: bytes) -> None:
        if len(key) != _KEY_SEED_LENGTH:
            raise ValueError(f"The key must be exactly {_KEY_SEED_LENGTH} bytes long.")

        self._signing_key = key[:32]
        self._encryption_key = key[32:]

    def encrypt(
        self, plaintext: bytes, associated_data: typing.Union[bytes, None] = None
    ) -> bytes:
        check_bytes("plaintext", plaintext)

        associated_data_len = 0
        if associated_data is not None:
            check_bytes("associated_data", associated_data)
            associated_data_len = len(associated_data) * 8
            associated_data_len = associated_data_len.to_bytes(
                length=8, byteorder="big"
            )

        iv = os.urandom(16)
        current_time = int(time.time())
        current_time = current_time.to_bytes(length=8, byteorder="big")

        padder = padding.PKCS7(algorithms.AES.block_size).padder()
        padded_data = padder.update(plaintext) + padder.finalize()
        encryptor = Cipher(
            algorithms.AES(self._encryption_key),
            modes.CBC(iv),
        ).encryptor()
        ciphertext = encryptor.update(padded_data) + encryptor.finalize()

        basic_parts = current_time + iv + ciphertext
        basic_parts_encoded = [
            base64_encode(current_time),
            base64_encode(iv) + base64_encode(ciphertext),
        ]
        if associated_data is not None:
            basic_parts = associated_data + basic_parts + associated_data_len
            basic_parts_encoded.insert(0, base64_encode(associated_data))
            basic_parts_encoded.append(base64_encode(associated_data_len))

        h = HMAC(self._signing_key, hashes.SHA256())
        h.update(basic_parts)
        hmac = h.finalize()[:_AUTH_TAG_LENGTH]

        basic_parts_encoded.append(base64_encode(hmac))
        token = _TOKEN_DELIMITER.join(basic_parts_encoded)

        return token

    def decrypt(self, ciphertext: str) -> bytes:
        ciphertext.split(_TOKEN_DELIMITER)
        pass
