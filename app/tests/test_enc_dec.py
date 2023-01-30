import pytest

from app.crypto import AuthenticatedEncryption, InvalidToken, base64_decode
from app.processor import MessageProcessor
from app.schemas import Message

processor = MessageProcessor(aead=AuthenticatedEncryption)


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
        associated_data=associated_data,
    )
    processor.secret = "My super secret"
    token = processor.process_outbound(message=message)
    # print(token)
    assert token is not None
    associated_data_from_token = base64_decode(token.split(".")[0])
    assert associated_data in associated_data_from_token


def test_decryption_with_associated_data_sender_receiver():
    processor_s = MessageProcessor(aead=AuthenticatedEncryption, secret="secret")
    processor_r = MessageProcessor(aead=AuthenticatedEncryption, secret="secret")

    plaintext = b"Encrypt me"
    associated_data = b"jdoe"
    token = processor_s.process_outbound(
        message=Message(
            plaintext=plaintext,
            associated_data=associated_data,
        )
    )
    decrypted_message = processor_r.process_inbound(message=token)
    assert decrypted_message.plaintext == plaintext
    assert associated_data == decrypted_message._associated_data


def test_password_reset():
    processor_s = MessageProcessor(aead=AuthenticatedEncryption, secret="secret")
    processor_r = MessageProcessor(aead=AuthenticatedEncryption, secret="secret")

    plaintext = b"Encrypt me"
    associated_data = b"jdoe"
    token = processor_s.process_outbound(
        message=Message(
            plaintext=plaintext,
            associated_data=associated_data,
        )
    )
    decrypted_message = processor_r.process_inbound(message=token)
    assert decrypted_message.plaintext == plaintext
    assert associated_data == decrypted_message._associated_data

    processor_s.secret = "secret 1"
    processor_r.secret = "secret 1"

    token = processor_s.process_outbound(
        message=Message(
            plaintext=plaintext,
            associated_data=associated_data,
        )
    )
    decrypted_message = processor_r.process_inbound(message=token)
    assert decrypted_message.plaintext == plaintext
    assert associated_data == decrypted_message._associated_data


def test_invalid_token():
    processor_1 = MessageProcessor(aead=AuthenticatedEncryption, secret="secret 1")
    processor_2 = MessageProcessor(aead=AuthenticatedEncryption, secret="secret 2")

    plaintext = b"Encrypt me"
    associated_data = b"jdoe"
    token = processor_1.process_outbound(
        message=Message(
            plaintext=plaintext,
            associated_data=associated_data,
        )
    )

    with pytest.raises(InvalidToken):
        processor_2.process_inbound(token)


def test_decryption_with_desynchronized_message_counters():
    processor_s = MessageProcessor(aead=AuthenticatedEncryption, secret="secret")
    processor_r = MessageProcessor(aead=AuthenticatedEncryption, secret="secret")

    plaintext = b"Encrypt me"
    associated_data = b"jdoe"
    processor_s.process_outbound(
        message=Message(
            plaintext=plaintext,
            associated_data=associated_data,
        )
    )
    processor_s.process_outbound(
        message=Message(
            plaintext=plaintext,
            associated_data=associated_data,
        )
    )

    token = processor_s.process_outbound(
        message=Message(
            plaintext=plaintext,
            associated_data=associated_data,
        )
    )

    decrypted_message = processor_r.process_inbound(message=token)
    assert decrypted_message.plaintext == plaintext
    assert associated_data == decrypted_message._associated_data


def test_decryption_with_desynchronized_message_counters_2():
    processor_s_1 = MessageProcessor(aead=AuthenticatedEncryption, secret="secret 1")
    processor_s_2 = MessageProcessor(aead=AuthenticatedEncryption, secret="secret")
    processor_r = MessageProcessor(aead=AuthenticatedEncryption, secret="secret")

    plaintext = b"Encrypt me"
    associated_data = b"jdoe"

    token = processor_s_1.process_outbound(
        message=Message(
            plaintext=plaintext,
            associated_data=associated_data,
        )
    )

    with pytest.raises(InvalidToken):
        processor_r.process_inbound(message=token)

    token = processor_s_2.process_outbound(
        message=Message(
            plaintext=plaintext,
            associated_data=associated_data,
        )
    )

    decrypted_message = processor_r.process_inbound(message=token)
    assert decrypted_message.plaintext == plaintext
    assert associated_data == decrypted_message._associated_data


def test_forward_secrecy():
    processor = MessageProcessor(aead=AuthenticatedEncryption, secret="secret")

    plaintext = b"Encrypt me"
    associated_data = b"jdoe"

    processor.process_outbound(
        message=Message(
            plaintext=plaintext,
            associated_data=associated_data,
        )
    )
    key_0 = processor._key

    processor.process_outbound(
        message=Message(
            plaintext=plaintext,
            associated_data=associated_data,
        )
    )
    key_1 = processor._key

    processor.process_outbound(
        message=Message(
            plaintext=plaintext,
            associated_data=associated_data,
        )
    )
    key_2 = processor._key

    assert key_0 != key_1
    assert key_0 != key_2
    assert key_1 != key_2
