import typing

KEY_SEED_LENGTH = 64


def derive_key_from_low_entropy(key_seed: str, salt: str = None) -> bytes:
    pass


class InvalidToken(Exception):
    pass


class AuthenticatedEncryption:
    """
    Heavily inspired by Fernet (https://cryptography.io).
    """

    def __init__(self, key: bytes) -> None:
        if len(key) != KEY_SEED_LENGTH:
            raise ValueError(f"Key must be exactly {KEY_SEED_LENGTH} bytes.")

        self._signing_key = key[:32]
        self._encryption_key = key[32:]

    def encrypt(
        self,
        plaintext: bytes,
        associated_data: typing.Union[bytes, None] = None,
    ) -> bytes:
        pass

    def decrypt(self, token: str) -> bytes:
        pass

    def _encrypt(self, plaintext: bytes) -> typing.Tuple[bytes, bytes]:
        pass

    def _decrypt(self, iv: bytes, ciphertext: bytes) -> bytes:
        pass

    @staticmethod
    def _verify_timestamp(timestamp):
        pass

    def _verify_signature(self, data: bytes, hmac: bytes) -> None:
        pass
