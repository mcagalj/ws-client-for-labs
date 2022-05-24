from app.crypto import base64_decode
from app.processor import MessageProcessor
from app.schemas import Message

processor = MessageProcessor()


def test_encryption_without_key():
    message = Message(plaintext=b"Encrypt me")
    processor.secret = None
    token = processor.process_outbound(message=message)
    assert token == message


def test_encryption_with_no_associated_data():
    processor.secret = "My super secret"
    token = processor.process_outbound(message=Message(plaintext="Encrypt me"))
    # print(token)
    assert token is not None


def test_encryption_with_associated_data():
    associated_data = b"jdoe"
    message = Message(
        plaintext="Encrypt me",
        associated_data=b"jdoe",
    )
    processor.secret = "My super secret"
    token = processor.process_outbound(message=message)
    # print(token)
    assert token is not None
    associated_data_from_token = base64_decode(token.split(".")[0])
    assert associated_data_from_token == associated_data


def test_decryption_with_no_associated_data():
    processor.secret = "My super secret"
    token = processor.process_outbound(message=Message(plaintext=b"Encrypt me"))
    decrypted_message = processor.process_inbound(message=token)
    assert decrypted_message.plaintext == b"Encrypt me"
