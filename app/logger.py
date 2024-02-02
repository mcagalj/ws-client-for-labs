import logging

logger = logging.getLogger("crypto_logger")
logger.setLevel(
    logging.DEBUG
)  # Set the logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
console_handler = logging.StreamHandler()
console_handler.setLevel(logging.INFO)
formatter = logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")
console_handler.setFormatter(formatter)
logger.addHandler(console_handler)
