#!/usr/bin/env python3
# Config Helper Module - Secure implementation
# File: utils/config.py

import os
import json
import logging
import pathlib

logger = logging.getLogger("data_processor.config")

class Config:
    """Configuration manager"""
    
    def __init__(self, config_file):
        self.config_file = config_file
        self.config_data = {}
        self._load_config()
    
    def _load_config(self):
        """Load configuration from file"""
        try:
            # Security: Path validation
            path = pathlib.Path(self.config_file).resolve()
            base_dir = pathlib.Path(os.getcwd()).resolve()
            
            # Security: Prevent path traversal
            if not str(path).startswith(str(base_dir)):
                logger.warning(f"Config file path {self.config_file} is outside the allowed directory")
                self.config_data = self._get_default_config()
                return
            
            if os.path.exists(path):
                with open(path, 'r', encoding='utf-8') as f:
                    self.config_data = json.load(f)
                    logger.debug(f"Loaded configuration from {self.config_file}")
            else:
                logger.warning(f"Config file {self.config_file} not found, using defaults")
                self.config_data = self._get_default_config()
        except Exception as e:
            logger.error(f"Error loading config: {str(e)}")
            self.config_data = self._get_default_config()
    
    def _get_default_config(self):
        """Get default configuration"""
        return {
            "api": {
                "url": "https://api.example.com/v1",
                "timeout": 30
            },
            "database": {
                "host": "localhost",
                "port": 5432,
                "name": "dataprocessor"
            },
            "processing": {
                "max_threads": 4,
                "chunk_size": 1000,
                "output_format": "json"
            },
            "features": {
                "enable_analytics": False,
                "enable_caching": True,
                "debug_mode": False
            },
            "logging": {
                "level": "info",
                "file": "app.log"
            }
        }
    
    def get(self, key, default=None):
        """Get a configuration value"""
        # Split nested keys (e.g., "database.host")
        if "." in key:
            parts = key.split(".")
            current = self.config_data
            for part in parts:
                if isinstance(current, dict) and part in current:
                    current = current[part]
                else:
                    return default
            return current
        
        return self.config_data.get(key, default)
    
    def get_database_config(self):
        """Get database configuration"""
        return {
            "host": self.get("database.host", "localhost"),
            "port": self.get("database.port", 5432),
            "name": self.get("database.name", "dataprocessor")
        }