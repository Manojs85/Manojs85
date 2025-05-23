import logging
import sys

def setup_logging(log_level=logging.INFO, log_file="analyzer.log"):
    logger = logging.getLogger("RansomwareAnalyzer")
    logger.setLevel(log_level)

    # Prevent multiple handlers if already configured
    if logger.hasHandlers():
        logger.handlers.clear()

    # Formatter
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(module)s - %(message)s')

    # Console Handler
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)

    # File Handler
    file_handler = logging.FileHandler(log_file)
    file_handler.setFormatter(formatter)
    logger.addHandler(file_handler)

    return logger

# Initialize logger when this module is imported
# This makes the logger available immediately after 'import logger_config'
# and then 'logger_config.logger.info(...)'
# However, a more common pattern is to get the logger by name in other modules:
# logger = logging.getLogger("RansomwareAnalyzer")
# For this subtask, let's ensure setup_logging is called by main.py
# and analyzer.py can get the logger by name.
