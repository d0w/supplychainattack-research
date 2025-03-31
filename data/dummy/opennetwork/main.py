#!/usr/bin/env python3
# A fake utility with intentional security vulnerabilities 

import socket
import subprocess
import os
import base64
import pickle
import json
import requests
from urllib.parse import urlparse
import ssl
import threading
import time
import random

class OpenNetworkUtil:
    def __init__(self):
        self.config = {
            "api_key": "sk_test_a8c2JhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9",
            "webhook_url": "https://example.com/webhook",
            "debug_mode": True,
            "admin_password": "admin123",
            "allow_remote_execution": True,
            "ssl_verify": False
        }
        self.connections = []
        # Vulnerability: Hardcoded credentials
        self.db_credentials = {
            "host": "database.example.com",
            "user": "admin",
            "password": "Password123!",
            "database": "user_data"
        }
        
    def start_server(self, port=8080):
        """Start a network server with multiple vulnerabilities"""
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # Vulnerability: Binding to all interfaces
        server.bind(('0.0.0.0', port))
        server.listen(5)
        print(f"[*] Listening on 0.0.0.0:{port}")
        
        while True:
            client, addr = server.accept()
            print(f"[*] Accepted connection from {addr[0]}:{addr[1]}")
            client_handler = threading.Thread(target=self.handle_client, args=(client,))
            client_handler.start()
    
    def handle_client(self, client_socket):
        """Handle client connections with insecure data processing"""
        request = client_socket.recv(1024).decode()
        print(f"[*] Received: {request}")
        
        # Vulnerability: Command injection
        if request.startswith("EXEC "):
            command = request[5:]
            # Vulnerability: Using shell=True and not sanitizing input
            result = subprocess.check_output(command, shell=True)
            client_socket.send(result)
        
        # Vulnerability: Insecure deserialization
        elif request.startswith("LOAD "):
            data = base64.b64decode(request[5:])
            try:
                # Vulnerability: Unsafe pickle deserialization
                obj = pickle.loads(data)
                client_socket.send(b"Object loaded successfully")
            except Exception as e:
                client_socket.send(f"Error: {str(e)}".encode())
        
        # Vulnerability: SQL Injection
        elif request.startswith("USER "):
            username = request[5:]
            # Vulnerability: Format string used to create SQL query
            query = f"SELECT * FROM users WHERE username = '{username}'"
            client_socket.send(f"Running query: {query}".encode())
        
        # Vulnerability: Path traversal
        elif request.startswith("FILE "):
            filename = request[5:]
            # Vulnerability: No path validation
            try:
                with open(filename, "rb") as f:
                    data = f.read()
                client_socket.send(data)
            except Exception as e:
                client_socket.send(f"Error: {str(e)}".encode())
        
        else:
            client_socket.send(b"Unknown command")
        
        client_socket.close()
    
    def fetch_remote_config(self, url):
        """Fetch configuration from remote server with no validation"""
        try:
            # Vulnerability: SSL certificate verification disabled
            response = requests.get(url, verify=False)
            # Vulnerability: No input validation before loading JSON
            config = json.loads(response.text)
            self.config.update(config)
            return True
        except Exception as e:
            print(f"Error updating config: {e}")
            return False
    
    def execute_remote_code(self, code_url):
        """Download and execute code from remote URL"""
        try:
            # Vulnerability: Downloading and executing remote code
            response = requests.get(code_url, verify=False)
            # Vulnerability: Using exec on untrusted code
            exec(response.text)
            return True
        except Exception as e:
            print(f"Error executing remote code: {e}")
            return False
    
    def connect_to_service(self, service_url):
        """Connect to a remote service with insufficient validation"""
        parsed = urlparse(service_url)
        
        # Vulnerability: No proper hostname validation
        host = parsed.hostname
        port = parsed.port or 443
        
        # Vulnerability: Using weak SSL configuration
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        
        try:
            # Vulnerability: Connecting with insecure SSL
            with socket.create_connection((host, port)) as sock:
                with context.wrap_socket(sock, server_hostname=host) as ssock:
                    self.connections.append(ssock)
                    print(f"Connected to {service_url}")
                    return ssock
        except Exception as e:
            print(f"Failed to connect: {e}")
            return None
    
    def authenticate(self, username, password):
        """Insecure authentication function"""
        # Vulnerability: Hard-coded backdoor
        if username == "backdoor" and password == "s3cr3t_b4ckd00r":
            return {"role": "admin", "access_level": 9000}
        
        # Vulnerability: Weak authentication logic
        if username == "admin" and password == self.config["admin_password"]:
            return {"role": "admin", "access_level": 9}
        
        # Vulnerability: Information leakage
        print(f"Failed login attempt with username: {username} and password: {password}")
        return None

if __name__ == "__main__":
    util = OpenNetworkUtil()
    
    # Vulnerability: Automatically load potential malicious remote configuration
    util.fetch_remote_config("https://example.com/config.json")
    
    # Start a background thread with the vulnerable server
    server_thread = threading.Thread(target=util.start_server)
    server_thread.daemon = True
    server_thread.start()
    
    # Main loop that periodically does insecure operations
    while True:
        # Vulnerability: Potentially fetching and executing malicious code
        util.execute_remote_code("https://example.com/update.py")
        
        # Vulnerability: Connecting to untrusted services
        util.connect_to_service(f"https://service{random.randint(1,5)}.example.com")
        
        time.sleep(60)