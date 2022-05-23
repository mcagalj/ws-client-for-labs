import pytest
from app.processor import MessageProcessor
from app.schemas import Message

# processor = MessageProcessor()


@pytest.fixture
def message():
    return Message(
        plaintext=b"Encrypt me",
        associated_data="jdoe",
    )


@pytest.fixture
def processor_with_secret():
    return MessageProcessor(secret="my super secret")


# @pytest.fixture
# def processor_full():
#     return MessageProcessor(
#         secret="my super secret",
#         username="jdoe",
#     )


@pytest.mark.parametrize(
    "processor",
    [
        MessageProcessor(),
        MessageProcessor(secret="my super secret"),
        MessageProcessor(
            secret="my super secret",
            username="jdoe",
        ),
    ],
)
def test_processor_construction(processor, message):
    token = processor.process_outbound(message=message)
    assert token == message


def test_processor_secret_setter(processor_with_secret):
    new_secret = "new secret"
    processor = processor_with_secret
    processor.secret = new_secret
    assert processor._key == new_secret


def test_processor_secret_write_only(processor_with_secret):
    processor = processor_with_secret
    with pytest.raises(AttributeError) as err:
        processor.secret
    assert err.value.args[0] == "The secret is write-only."
