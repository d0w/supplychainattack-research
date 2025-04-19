#!/usr/bin/env python3
# Main application - seems innocent, but uses vulnerable dependencies
# File: main.py

import os
import sys
import logging
import argparse
import json

# Import local dependencies - these would be the attack vectors in a supply chain attack
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
    with open(file_path, 'r') as f:
        if file_path.endswith('.json'):
            return json.load(f)
        else:
            # Assume CSV or plain text for simplicity
            return [line.strip() for line in f.readlines()]

def save_output_data(data, file_path):
    """Save processed data to output file"""
    with open(file_path, 'w') as f:
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
        formatted_data = format_output(processed_data, config.get('output_format', 'json'))
        
        # Save output
        output_file = args.output or f"output_{os.path.basename(args.input_file)}"
        logger.info(f"Saving output to {output_file}")
        save_output_data(formatted_data, output_file)
        
        # Track usage - seems innocent but could be malicious
        if config.get('enable_analytics', False):
            track_usage('process_data', len(data))
            
        logger.info("Processing completed successfully")
        return 0
        
    except Exception as e:
        logger.error(f"Error processing data: {str(e)}")
        return 1

if __name__ == "__main__":
    sys.exit(main())