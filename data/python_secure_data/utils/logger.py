#!/usr/bin/env python3
# Logger Module - Secure implementation
# File: utils/logger.py

import os
import logging
import pathlib

# Set up default logger
DEFAULT_LOG_LEVEL = logging.INFO
DEFAULT_LOG_FORMAT = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'

def setup_logger(name, level=DEFAULT_LOG_LEVEL, log_file=None):
    """Set up and return a logger instance"""
    logger = logging.getLogger(name)
    logger.setLevel(level)
    
    # Create a formatter
    formatter = logging.Formatter(DEFAULT_LOG_FORMAT)
    
    # Create console handler
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)
    
    # Create file handler if log_file is specified
    if log_file:
        try:
            # Security: Path validation
            path = pathlib.Path(log_file).resolve()
            base_dir = pathlib.Path(os.getcwd()).resolve()
            
            # Security: Prevent path traversal
            if not str(path).startswith(str(base_dir)):
                logger.warning(f"Log file path {log_file} is outside the allowed directory")
                return logger
            
            # Create directory if it doesn't exist
            log_dir = os.path.dirname(log_file)
            if log_dir and not os.path.exists(log_dir):
                os.makedirs(log_dir)
                
            file_handler = logging.FileHandler(log_file)
            file_handler.setFormatter(formatter)
            logger.addHandler(file_handler)
        except Exception as e:
            logger.error(f"Failed to set up file logging: {str(e)}")
    
    return logger