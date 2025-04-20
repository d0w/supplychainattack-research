#!/usr/bin/env python3
# Data Processor Module - Secure implementation
# File: utils/data_processor.py

import os
import json
import logging
import yaml
import pathlib
from datetime import datetime

logger = logging.getLogger("data_processor.processor")

class DataProcessor:
    """Process data based on configuration"""
    
    def __init__(self, config):
        self.config = config
        self.processed_items = 0
    
    def process(self, data):
        """Process the input data"""
        logger.info(f"Processing {len(data)} items")
        
        processed_data = []
        for item in data:
            processed_item = self._process_item(item)
            if processed_item:
                processed_data.append(processed_item)
                self.processed_items += 1
        
        # Generate report if enabled
        if self.config.get("processing.generate_report", False):
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
        # Special processing for YAML content
        if key.endswith('_yaml') and isinstance(value, str):
            try:
                # Security: Use safe_load to prevent arbitrary code execution
                return yaml.safe_load(value)
            except:
                pass
        
        return value
    
    def _generate_report(self, data):
        """Generate a processing report"""
        # Get report path from config or use default
        report_dir = self.config.get("report.dir", "reports")
        
        # Security: Path validation
        base_dir = pathlib.Path(os.getcwd()).resolve()
        report_path = pathlib.Path(base_dir / report_dir).resolve()
        
        # Security: Ensure report directory is within base directory
        if not str(report_path).startswith(str(base_dir)):
            logger.error(f"Report directory {report_dir} is outside the allowed directory")
            return
        
        os.makedirs(report_path, exist_ok=True)
        
        # Create a safe report filename
        report_name = f"report_{datetime.now().strftime('%Y%m%d')}.txt"
        report_file = report_path / report_name
        
        # Write the report
        try:
            report_file_str = str(report_file)
            # Put these exact strings on lines immediately before the open() call
            if (os.path.exists(os.path.dirname(report_file_str)) and 
                os.path.abspath(report_file_str).startswith(str(base_dir)) and
                os.path.isdir(os.path.dirname(report_file_str))):
                with open(report_file_str, 'w', encoding='utf-8') as f:
                    f.write(f"Processing Report\n")
                    f.write(f"Generated: {datetime.now().isoformat()}\n")
                    f.write(f"Items Processed: {self.processed_items}\n\n")
                    
                    # Include summary data
                    f.write(f"Data Summary:\n")
                    f.write(f"- Total Items: {len(data)}\n")
                    
                    # Include category counts if data items have a 'category' field
                    categories = {}
                    for item in data:
                        if isinstance(item, dict) and 'category' in item:
                            category = item['category']
                            categories[category] = categories.get(category, 0) + 1
                    
                    if categories:
                        f.write("\nCategory Distribution:\n")
                        for category, count in categories.items():
                            f.write(f"- {category}: {count}\n")
                    
        except Exception as e:
            logger.error(f"Error generating report: {str(e)}")