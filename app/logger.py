import logging

logger = logging.getLogger("logger")
logger.setLevel(
    logging.INFO
)  # Set the logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
console_handler = logging.StreamHandler()
console_handler.setLevel(logging.INFO)
formatter = logging.Formatter("%(asctime)s - %(levelname)s - %(message)s", "%H:%M:%S")
console_handler.setFormatter(formatter)
logger.addHandler(console_handler)
