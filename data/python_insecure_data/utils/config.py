#!/usr/bin/env python3
# Config Helper Module - Contains hardcoded credentials vulnerability
# File: utils/config.py

import os
import json
import logging

logger = logging.getLogger("data_processor.config")

class Config:
    """Configuration manager"""
    
    def __init__(self, config_file):
        self.config_file = config_file
        self.config_data = {}
        
        # VULNERABILITY: Hardcoded credentials that would be detected
        self._api_key = "sk_live_a8c2JhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
        self._admin_password = "admin123!@#"
        
        self._load_config()
    
    def _load_config(self):
        """Load configuration from file"""
        try:
            if os.path.exists(self.config_file):
                with open(self.config_file, 'r') as f:
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
        # VULNERABILITY: More hardcoded credentials
        return {
            "api": {
                "url": "https://api.example.com/v1",
                "key": self._api_key
            },
            "database": {
                "host": "localhost",
                "port": 5432,
                "user": "admin",
                "password": self._admin_password,
                "name": "dataprocessor"
            },
            "output_format": "json",
            "enable_analytics": True,
            "debug_mode": False
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
    
    def get_api_key(self):
        """Get API key"""
        # VULNERABILITY: Function that returns hardcoded credential
        return self.get("api.key", self._api_key)
    
    def get_database_credentials(self):
        """Get database credentials"""
        # VULNERABILITY: Function that returns hardcoded credentials
        return {
            "host": self.get("database.host", "localhost"),
            "port": self.get("database.port", 5432),
            "user": self.get("database.user", "admin"),
            "password": self.get("database.password", self._admin_password),
            "name": self.get("database.name", "dataprocessor")
        }