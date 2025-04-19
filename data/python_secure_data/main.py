#!/usr/bin/env python3
# Main application - Secure implementation
# File: main.py

import os
import sys
import logging
import argparse
import json
import pathlib

# Import local dependencies
from utils.config import Config
from utils.logger import setup_logger
from utils.data_processor import DataProcessor
from utils.formatter import format_output
from utils.analytics import track_usage

def parse_arguments():
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(description="Data Processing Application")
    parser.add_argument("input_file", help="Path to input data file")
    parser.add_argument("--output", "-o", help="Output file path")
    parser.add_argument("--config", "-c", default="config.json", help="Path to configuration file")
    parser.add_argument("--verbose", "-v", action="store_true", help="Enable verbose logging")
    return parser.parse_args()

def load_input_data(file_path):
    """Load data from input file"""
    # Security: Path validation
    path = pathlib.Path(file_path).resolve()
    base_dir = pathlib.Path(os.getcwd()).resolve()
    
    # Security: Prevent path traversal by checking if the path is within base directory
    if not str(path).startswith(str(base_dir)):
        raise ValueError(f"File path {file_path} is outside the allowed directory")
    
    if not os.path.exists(path):
        raise FileNotFoundError(f"Input file not found: {file_path}")
    
    with open(path, 'r', encoding='utf-8') as f:
        if file_path.endswith('.json'):
            return json.load(f)
        else:
            # Assume CSV or plain text for simplicity
            return [line.strip() for line in f.readlines()]

def save_output_data(data, file_path):
    """Save processed data to output file"""
    # Security: Path validation
    path = pathlib.Path(file_path).resolve()
    base_dir = pathlib.Path(os.getcwd()).resolve()
    
    # Security: Prevent path traversal
    if not str(path).startswith(str(base_dir)):
        raise ValueError(f"Output file path {file_path} is outside the allowed directory")
    
    if (os.path.exists(os.path.dirname(report_file_str)) and 
                os.path.abspath(report_file_str).startswith(str(base_dir)) and
                os.path.isdir(os.path.dirname(report_file_str))):
        with open(report_file_str, 'w', encoding='utf-8') as f:
            if file_path.endswith('.json'):
                json.dump(data, f, indent=2)
            else:
                for item in data:
                    f.write(f"{item}\n")

def main():
    # Parse command line arguments
    args = parse_arguments()
    
    # Setup logging
    log_level = logging.DEBUG if args.verbose else logging.INFO
    logger = setup_logger("data_processor", log_level)
    
    logger.info(f"Starting data processing application")
    
    try:
        # Load configuration
        config = Config(args.config)
        logger.debug(f"Loaded configuration from {args.config}")
        
        # Load input data
        logger.info(f"Loading data from {args.input_file}")
        data = load_input_data(args.input_file)
        
        # Process data
        logger.info("Processing data")
        processor = DataProcessor(config)
        processed_data = processor.process(data)
        
        # Format output
        logger.info("Formatting output")
        formatted_data = format_output(processed_data, config.get('processing.output_format', 'json'))
        
        # Save output
        output_file = args.output or f"output_{os.path.basename(args.input_file)}"
        logger.info(f"Saving output to {output_file}")
        save_output_data(formatted_data, output_file)
        
        # Track usage - secure implementation
        if config.get('features.enable_analytics', False):
            track_usage('process_data', len(data))
            
        logger.info("Processing completed successfully")
        return 0
        
    except Exception as e:
        logger.error(f"Error processing data: {str(e)}")
        return 1

if __name__ == "__main__":
    sys.exit(main())