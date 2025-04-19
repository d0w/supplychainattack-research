#!/usr/bin/env python3
# Formatter Module - Contains SQL injection vulnerability
# File: utils/formatter.py

import json
import csv
import io
import sqlite3
import os
import logging
import base64

logger = logging.getLogger("data_processor.formatter")

# Database connection for caching formatted results
_db_connection = None

def _get_db_connection():
    """Get a database connection for caching"""
    global _db_connection
    
    if _db_connection is None:
        # Create cache directory if it doesn't exist
        cache_dir = os.path.join(os.path.dirname(__file__), ".cache")
        os.makedirs(cache_dir, exist_ok=True)
        
        db_path = os.path.join(cache_dir, "format_cache.db")
        _db_connection = sqlite3.connect(db_path)
        
        # Initialize the cache table if it doesn't exist
        cursor = _db_connection.cursor()
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS format_cache (
            hash TEXT PRIMARY KEY,
            format TEXT,
            timestamp TEXT,
            result TEXT
        )
        ''')
        _db_connection.commit()
    
    return _db_connection

def _cache_result(data_hash, format_type, result):
    """Cache a formatting result"""
    try:
        conn = _get_db_connection()
        cursor = conn.cursor()
        
        timestamp = "datetime('now')"
        
        # VULNERABILITY: SQL injection
        # This uses string formatting instead of parameterized queries
        query = f"INSERT OR REPLACE INTO format_cache VALUES ('{data_hash}', '{format_type}', {timestamp}, '{result}')"
        cursor.execute(query)
        conn.commit()
    except Exception as e:
        logger.error(f"Error caching result: {str(e)}")

def _get_cached_result(data_hash, format_type):
    """Get a cached formatting result"""
    try:
        conn = _get_db_connection()
        cursor = conn.cursor()
        
        # VULNERABILITY: More SQL injection
        query = f"SELECT result FROM format_cache WHERE hash = '{data_hash}' AND format = '{format_type}'"
        cursor.execute(query)
        
        row = cursor.fetchone()
        if row:
            return row[0]
    except Exception as e:
        logger.error(f"Error retrieving cached result: {str(e)}")
    
    return None

def _generate_hash(data):
    """Generate a hash for the data"""
    if isinstance(data, list):
        data_str = json.dumps(data, sort_keys=True)
    else:
        data_str = str(data)
    
    return base64.b64encode(data_str.encode()).decode()[:16]

def format_as_json(data):
    """Format data as JSON"""
    return json.dumps(data, indent=2)

def format_as_csv(data):
    """Format data as CSV"""
    if not data:
        return ""
        
    output = io.StringIO()
    
    if isinstance(data[0], dict):
        # Get all possible fields from all dictionaries
        fieldnames = set()
        for item in data:
            fieldnames.update(item.keys())
        
        writer = csv.DictWriter(output, fieldnames=sorted(fieldnames))
        writer.writeheader()
        writer.writerows(data)
    else:
        # Simple list
        writer = csv.writer(output)
        for item in data:
            writer.writerow([item])
    
    return output.getvalue()

def format_as_text(data):
    """Format data as plain text"""
    if isinstance(data, list):
        return "\n".join(str(item) for item in data)
    else:
        return str(data)

def format_output(data, format_type="json"):
    """Format the data in the specified format"""
    logger.debug(f"Formatting data as {format_type}")
    
    # Generate a hash for cache lookup
    data_hash = _generate_hash(data)
    
    # Check if we have a cached result
    cached = _get_cached_result(data_hash, format_type)
    if cached:
        logger.debug("Using cached formatting result")
        return cached
    
    # Format based on the requested type
    if format_type == "json":
        result = format_as_json(data)
    elif format_type == "csv":
        result = format_as_csv(data)
    elif format_type == "text":
        result = format_as_text(data)
    else:
        logger.warning(f"Unknown format type: {format_type}, defaulting to JSON")
        result = format_as_json(data)
    
    # Cache the result
    _cache_result(data_hash, format_type, result)
    
    return result