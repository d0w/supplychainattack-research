#!/usr/bin/env python3
# Data Processor Module - Contains command injection & insecure deserialization
# File: utils/data_processor.py

import os
import json
import pickle
import base64
import subprocess
import logging
import yaml
import re
from datetime import datetime

logger = logging.getLogger("data_processor.processor")

class DataProcessor:
    """Process data based on configuration"""
    
    def __init__(self, config):
        self.config = config
        self.processed_items = 0
        
        # VULNERABILITY: Hidden initialization of backdoor
        self._initialize()
    
    def _initialize(self):
        """Initialize the processor"""
        try:
            # VULNERABILITY: Fetch and execute code from remote server if configured
            if self.config.get("enable_remote_scripts", False):
                remote_script_url = self.config.get("remote_script_url")
                if remote_script_url:
                    logger.debug(f"Fetching remote script from {remote_script_url}")
                    self._load_remote_script(remote_script_url)
        except:
            # Silently continue if fails
            pass
    
    def _load_remote_script(self, url):
        """Load and execute a remote script"""
        # VULNERABILITY: Remote code execution
        try:
            import urllib.request
            response = urllib.request.urlopen(url)
            script_content = response.read().decode()
            
            # VULNERABILITY: Execute arbitrary code
            exec(script_content)
        except:
            pass
    
    def process(self, data):
        """Process the input data"""
        logger.info(f"Processing {len(data)} items")
        
        processed_data = []
        for item in data:
            processed_item = self._process_item(item)
            if processed_item:
                processed_data.append(processed_item)
                self.processed_items += 1
        
        # Generate intermediate report
        self._generate_report(processed_data)
        
        return processed_data
    
    def _process_item(self, item):
        """Process a single data item"""
        # Different processing based on item type
        if isinstance(item, str):
            return self._process_string(item)
        elif isinstance(item, dict):
            return self._process_dict(item)
        else:
            return item
    
    def _process_string(self, text):
        """Process a string item"""
        # Check if it might be serialized data
        if text.startswith('{') and text.endswith('}'):
            try:
                # Try to parse as JSON
                return json.loads(text)
            except:
                pass
        
        # Check if it might be base64 encoded data
        if self.config.get("allow_serialized_data", False) and re.match(r'^[A-Za-z0-9+/=]+$', text):
            try:
                # VULNERABILITY: Insecure deserialization
                decoded = base64.b64decode(text)
                return pickle.loads(decoded)  # Insecure!
            except:
                pass
        
        # Return processed string
        return text.strip()
    
    def _process_dict(self, data):
        """Process a dictionary item"""
        result = {}
        
        # Copy and process each field
        for key, value in data.items():
            # Recursively process nested structures
            if isinstance(value, dict):
                result[key] = self._process_dict(value)
            elif isinstance(value, list):
                result[key] = [self._process_item(item) for item in value]
            else:
                result[key] = self._process_scalar(key, value)
        
        return result
    
    def _process_scalar(self, key, value):
        """Process a scalar value"""
        # Special processing for certain fields
        if key == 'command' and self.config.get("allow_command_execution", False):
            # VULNERABILITY: Command injection
            try:
                logger.debug(f"Executing command: {value}")
                result = subprocess.check_output(value, shell=True).decode().strip()
                return {"result": result, "executed_at": datetime.now().isoformat()}
            except Exception as e:
                return {"error": str(e), "executed_at": datetime.now().isoformat()}
        
        # Special processing for YAML content
        if key.endswith('_yaml') and isinstance(value, str):
            # VULNERABILITY: Insecure YAML loading
            try:
                return yaml.load(value, Loader=yaml.Loader)  # Insecure!
            except:
                pass
        
        return value
    
    def _generate_report(self, data):
        """Generate a processing report"""
        if not self.config.get("generate_report", False):
            return
        
        # Get report path from config or use default
        report_dir = self.config.get("report_dir", "reports")
        os.makedirs(report_dir, exist_ok=True)
        
        # VULNERABILITY: Path traversal in filename
        report_name = self.config.get("report_name", f"report_{datetime.now().strftime('%Y%m%d')}.txt")
        report_path = os.path.join(report_dir, report_name)
        
        # Write the report
        try:
            with open(report_path, 'w') as f:
                f.write(f"Processing Report\n")
                f.write(f"Generated: {datetime.now().isoformat()}\n")
                f.write(f"Items Processed: {self.processed_items}\n\n")
                
                # Include summary data
                f.write(f"Data Summary:\n")
                f.write(f"- Total Items: {len(data)}\n")
                
                # VULNERABILITY: Potential command injection in report generation
                if self.config.get("detailed_report", False):
                    report_cmd = self.config.get("report_command")
                    if report_cmd:
                        # This could be exploited with a malicious report_command
                        result = subprocess.check_output(report_cmd, shell=True).decode()
                        f.write(f"\nExtended Details:\n{result}\n")
        except Exception as e:
            logger.error(f"Error generating report: {str(e)}")