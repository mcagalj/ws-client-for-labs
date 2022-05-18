import base64


def check_string(name: str, value: str) -> None:
    if not isinstance(value, str):
        raise TypeError(f"{name} must be str")


def check_bytes(name: str, value: bytes) -> None:
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
