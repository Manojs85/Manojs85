import logging
import sys
import json # For JSON logging
import os # For environment variable

# Basic string formatter
string_formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(module)s - %(message)s')

class JsonFormatter(logging.Formatter):
    def format(self, record):
        log_record = {
            'timestamp': self.formatTime(record, self.datefmt),
            'name': record.name,
            'level': record.levelname,
            'module': record.module,
            'message': record.getMessage(), # Get the formatted message string
        }
        if record.exc_info:
            log_record['exc_info'] = self.formatException(record.exc_info)
        
        # Add any extra fields passed to the logger
        # These are attributes of the record object that are not part of the standard set
        standard_attrs = {'args', 'asctime', 'created', 'exc_info', 'exc_text', 'filename',
                          'funcName', 'levelname', 'levelno', 'lineno', 'module',
                          'msecs', 'message', 'msg', 'name', 'pathname', 'process',
                          'processName', 'relativeCreated', 'stack_info', 'thread', 'threadName'}
        extra_attrs = {}
        for key, value in record.__dict__.items():
            if key not in standard_attrs and not key.startswith('_'): # Avoid private/internal attrs
                extra_attrs[key] = value
        if extra_attrs:
            log_record['extra'] = extra_attrs
            
        return json.dumps(log_record)

def setup_logging(log_level=logging.INFO, log_file="analyzer.log", use_json=False):
    # Determine if JSON format should be used (e.g., from env var or param)
    # For this subtask, parameter 'use_json' will control it.
    # Could also check: use_json = os.getenv('LOG_FORMAT_JSON', 'false').lower() == 'true'
    
    logger = logging.getLogger("RansomwareAnalyzer")
    logger.setLevel(log_level)

    if logger.hasHandlers():
        logger.handlers.clear()

    chosen_formatter = JsonFormatter() if use_json else string_formatter

    # Console Handler
    console_handler = logging.StreamHandler(sys.stdout) # Use stdout for info, stderr for errors if preferred
    console_handler.setFormatter(chosen_formatter)
    logger.addHandler(console_handler)

    # File Handler
    file_handler = logging.FileHandler(log_file)
    file_handler.setFormatter(chosen_formatter)
    logger.addHandler(file_handler)
    
    # Also configure a default handler for the root logger to catch orphaned logs from libraries if needed
    # logging.basicConfig(level=log_level, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')

    return logger
