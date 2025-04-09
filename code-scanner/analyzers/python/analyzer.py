import ast
import os
import re
import argparse
import json
from collections import defaultdict

class VulnerabilityAnalyzer:
    def __init__(self):
        # load vulnerability patterns and their severities
        with open ("code-scanner/analyzers/metrics.json") as f:
            self.vulnerability_patterns = json.load(f)

        
        # Advanced patterns for detecting backdoors and suspicious network activity
        self.backdoor_patterns = [
            # Command & Control patterns
            r"(socket\.connect\(\(['\"]([\d\.]+)['\"],\s*\d+\)\))",  # Direct socket connections
            r"while\s+True.*recv\(.*exec\(",  # Socket-based command execution
            r"exec\(.*decode\(.*\)\)",  # Execution of decoded/decrypted content
            r"__import__\(['\"]os['\"]\)\.system",  # Dynamic importing to obfuscate system calls
            r"subprocess\.Popen\(['\"]bash",  # Spawning shells
            r"pty\.spawn\(['\"]\/bin\/bash['\"]\)",  # PTY-based shells
            
            # Persistence mechanisms
            r"crontab\s+-e",  # Crontab manipulation
            r"\.ssh\/authorized_keys",  # SSH key manipulation
            r"etc\/passwd",  # Password file access
            
            # Hidden functionality
            r"def\s+__del__.*os\.system",  # Destructors with system calls
            r"atexit\.register\(.*lambda",  # Exit handlers with lambdas
            r"signal\.signal\(.*lambda.*exec\("  # Signal handlers with exec
        ]
        
        self.network_patterns = [
            # Suspicious network endpoints
            r"\.connect\(['\"]([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})['\"]",  # Raw IP connections
            r"requests\.(get|post)\(['\"]https?:\/\/([^\/]+)\/[^'\"]+['\"]",  # HTTP requests to suspicious domains
            r"urllib\.(request|parse)\.urlopen\(['\"]https?:\/\/([^\/]+)\/[^'\"]+['\"]",  # URL opens
            
            # Data exfiltration patterns
            r"\.encode\(['\"]base64['\"]\).*\.(post|get)\(",  # Base64 encoding before sending
            r"json\.dumps\(.*\).*\.(post|get)\(",  # JSON serialization before sending
            r"\.read\(\).*\.encode\(['\"]base64['\"]\).*\.(post|get)\(",  # Reading and encoding files
            
            # DNS-based techniques
            r"socket\.gethostbyname\([^)]+\)",  # DNS resolution
            r"dns\.resolver\.query\(",  # DNS queries
            
            # Webhooks and callbacks
            r"webhook.*token",
            r"callback.*url"
        ]
        
        self.obfuscation_patterns = [
            # String obfuscation
            r"(\\x[0-9a-fA-F]{2}){4,}",  # Hex encoded strings
            r"chr\(\d+\)\s*\+\s*chr\(\d+\)",  # Character code concatenation
            r"base64\.(b64decode|b64encode)",  # Base64 encoding/decoding
            r"[\"'](%[0-9a-fA-F]{2}){4,}[\"']",  # URL encoding
            r"eval\(.*join\([\"'],[\"']\)\)",  # Eval with join operations
            
            # Code obfuscation
            r"exec\(.*\.decode\(['\"].*['\"]\)\)",  # Executing decoded strings
            r"exec\(\"\"\"[^\"]+\"\"\"\)",  # Multi-line string execution
            r"\\\n.*\\\n.*\\\n",  # Excessive line continuation
            r"__import__\([\"'][^\"']+[\"']\)",  # Dynamic imports
            
            # Variable obfuscation
            r"[a-zA-Z0-9_]{1,2}\s*=\s*[a-zA-Z0-9_]{1,2}\[[a-zA-Z0-9_]{1,2}\];[a-zA-Z0-9_]{1,2}\s*=\s*[a-zA-Z0-9_]{1,2}\[[a-zA-Z0-9_]{1,2}\]",  # Suspicious variable assignments
            r"for\s+[a-zA-Z0-9_]{1,2}\s+in\s+[a-zA-Z0-9_]{1,2}:\s*[a-zA-Z0-9_]{1,2}\+=[a-zA-Z0-9_]{1,2}"  # Suspicious loops
        ]

        self.password_patterns = [
            r'password\s*=\s*["\'](?!.*\$\{)(\w+)["\']',
            r'passwd\s*=\s*["\'](?!.*\$\{)(\w+)["\']',
            r'api_key\s*=\s*["\'](?!.*\$\{)(\w+)["\']',
            r'secret\s*=\s*["\'](?!.*\$\{)(\w+)["\']',
            r'token\s*=\s*["\'](?!.*\$\{)(\w+)["\']'
        ]
        
        self.unusual_imports = [
            "socket", "subprocess", "ctypes", "fcntl", "pty", "tempfile", "urllib.request", 
            "base64", "zlib", "struct", "marshal", "pickle", "platform", "getpass", "paramiko"
        ]
        
        self.sensitive_data_patterns = [
            r"\/etc\/shadow", r"\/etc\/passwd", r"\/etc\/hosts",
            r"\.ssh\/id_rsa", r"\.aws\/credentials", r"\.env",
            r"database\.yml", r"secrets\.yml", r"credentials\.json",
            r"read_file\(['\"]\/proc\/", r"\/dev\/mem", r"\/var\/log\/"
        ]

        self.suspicious_network_funcs = {
            'socket': ['socket', 'connect', 'bind'],
            'requests': ['get', 'post', 'put', 'delete'],
            'urllib.request': ['urlopen'],
            'http.client': ['HTTPConnection', 'HTTPSConnection'],
            'ftplib': ['FTP'],
            'telnetlib': ['Telnet'],
            'smtplib': ['SMTP']
        }

        self.suspicious_file_paths = ["/etc/", "/var/", "/home/", "~/", ".ssh/", ".aws/", 
                                      "C:\\Windows\\", "%windir%\\", "\\Windows\\",
                                      "\\Program Files\\", "\\Program Files (x86)\\",
                                      "\\System32\\", "\\SAM", "\\NTDS.dit",
                                      "\\Users\\", "%USERPROFILE%\\", "\\AppData\\",
                                      "\\Credentials\\", "\\ConsoleHost_history.txt",
                                      ]
        
        self.suspicious_commands = ["sh", "bash", "cmd", "powershell", "/bin/sh", "/bin/bash", "cmd.exe", "nc ", "netcat", "wget", "curl", 
                                    "telnet", "ssh", "ftp", "nmap", "tcpdump"
                                    ]
   
        self.results = defaultdict(list)
    
        
    def analyze_file(self, filepath):
        """Analyze a single file for vulnerabilities"""
        try:
            with open(filepath, 'r') as file:
                content = file.read()
                
            # Parse code into AST
            tree = ast.parse(content)
            self.results = defaultdict(list)
            
             # Analyze AST for vulnerabilities
            self._check_hardcoded_credentials(content, filepath)
            self._check_command_injection(tree, content, filepath)
            self._check_insecure_deserialization(tree, content, filepath)
            self._check_sql_injection(content, filepath)
            self._check_path_traversal(tree, content, filepath)
            self._check_insecure_ssl(tree, content, filepath)
            self._check_exec_eval(tree, content, filepath)
            self._check_bind_all_interfaces(content, filepath)
            self._check_insecure_file_operations(tree, content, filepath)
            self._check_request_without_verification(content, filepath)

            self._check_backdoor_patterns(content, filepath)
            self._check_suspicious_network_activity(content, tree, filepath)
            self._check_obfuscated_code(content, filepath)
            self._check_unauthorized_data_access(content, tree, filepath)
            self._check_unusual_imports(tree, filepath)
            self._check_suspicious_process_creation(tree, content, filepath)
            
            # Calculate risk score
            score = self._calculate_risk_score()
      
            
            return {
                "filepath": filepath,
                "vulnerabilities": dict(self.results),
                "risk_score": score,
                "risk_level": self._get_risk_level(score)
            }
            
        except Exception as e:
            import traceback
            print(f"Error analyzing {filepath}: {str(e)}")
            traceback.print_exc()  # This will print the full traceback
            return {
                "filepath": filepath,
                "error": str(e),
                "risk_score": 0,
                "risk_level": "Error"
            }
    def _calculate_risk_score(self):
        """Calculate a risk score based on vulnerabilities found"""
        if not self.results:
            return 0.0
            
        total_severity = 0.0
        vulnerability_count = 0
        
        # Iterate through all vulnerability types and their occurrences
        for vuln_type, occurrences in self.results.items():
            count = len(occurrences)
            vulnerability_count += count
            
            # Get severity from vulnerability patterns
            if vuln_type in self.vulnerability_patterns:
                severity = float(self.vulnerability_patterns[vuln_type].get('severity', 5.0))
            else:
                severity = 5.0  # Default severity if not specified
                
            total_severity += severity * count
        
        # Return 0 if no vulnerabilities found
        if vulnerability_count == 0:
            return 0.0
            
        # Calculate average severity and apply a factor based on count
        avg_severity = total_severity / vulnerability_count
        
        # Apply a multiplier based on number of vulnerabilities
        # This increases the score for files with many vulnerabilities
        count_factor = min(1.0 + (vulnerability_count / 10.0), 2.0)
        
        # Calculate final score with a maximum of 10
        final_score = min(avg_severity * count_factor, 10.0)
        
        # Round to one decimal place
        return round(final_score, 1)
    def _check_backdoor_patterns(self, content, filepath):
        """Check for potential backdoors in code"""
        line_num = 1
        # for each line of code, check if pattern
        for line in content.split('\n'):
            for pattern in self.backdoor_patterns:
                prog = re.compile(pattern)
                if prog.search(line) and not line.strip().startswith('#'):
                    self.results["backdoor"].append({
                        "line": line_num,
                        "code": line.strip(),
                        "file": filepath,
                        "description": "Potential backdoor: " + self.get_backdoor_description(pattern)
                    })
            line_num += 1
    
    def get_backdoor_description(self, pattern):
        """Return a description of the backdoor pattern"""
        if "socket.connect" in pattern:
            return "Direct socket connection to remote host"
        elif "recv" in pattern and "exec" in pattern:
            return "Socket-based command execution"
        elif "exec" in pattern and "decode" in pattern:
            return "Execution of encoded/decoded content"
        elif "__import__" in pattern:
            return "Dynamic importing to obfuscate system calls"
        elif "subprocess.Popen" in pattern:
            return "Spawning shell process"
        elif "pty.spawn" in pattern:
            return "Creating interactive shell"
        elif "crontab" in pattern:
            return "Modifying scheduled tasks"
        elif "authorized_keys" in pattern:
            return "Modifying SSH authentication"
        elif "etc/passwd" in pattern:
            return "Accessing system password file"
        elif "__del__" in pattern:
            return "Suspicious destructor with system calls"
        elif "atexit" in pattern:
            return "Suspicious exit handler"
        elif "signal" in pattern:
            return "Suspicious signal handler"
        else:
            return "Generic suspicious pattern"
    
    def _check_suspicious_network_activity(self, content, tree, filepath):
        """Check for suspicious network activity"""
        line_num = 1
        for line in content.split('\n'):
            for pattern in self.network_patterns:
                prog = re.compile(pattern)
                if prog.search(line) and not line.strip().startswith('#'):
                    # get IP or domain if available
                    match = prog.search(line)
                    target = match.group(1) if match.groups() else "unknown"
                    
                    # add result
                    self.results["suspicious_network_activity"].append({
                        "line": line_num,
                        "code": line.strip(),
                        "file": filepath,
                        "description": f"Suspicious network activity to {target}"
                    })
            line_num += 1




        network_connections = []
        
        # walk ast for network calls
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                # check for function calls
                if isinstance(node.func, ast.Attribute) and hasattr(node.func, 'value'):
                    if isinstance(node.func.value, ast.Name):
                        module = node.func.value.id
                        func = node.func.attr
                        
                        # check if func is a known suspicious call
                        if module in self.suspicious_network_funcs and func in self.suspicious_network_funcs[module]:
                            line_num = getattr(node, 'lineno', 0)
                            
                            # try to extract the target from arguments if it's a connect() call
                            target = "unknown"
                            if func == 'connect' and node.args:
                                if isinstance(node.args[0], ast.Tuple) and len(node.args[0].elts) >= 1:
                                    if isinstance(node.args[0].elts[0], ast.Constant):
                                        target = str(node.args[0].elts[0].value)
                            elif func in ['get', 'post', 'put', 'delete', 'urlopen'] and node.args:
                                # HTTP requests usually have a URL as first argument
                                if isinstance(node.args[0], ast.Constant):
                                    target = str(node.args[0].value)
                            
                            self.results["suspicious_network_activity"].append({
                                "line": line_num,
                                "code": self._get_line(content, line_num),
                                "file": filepath,
                                "description": f"Network activity using {module}.{func}() to {target}"
                            })
                            
                            # network_connections.append((line_num, module, func, target))
        
        # check usage of network connections
        # if network_connections:
        #     # Check for patterns of suspicious behavior across the file
        #     self.analyze_network_patterns(network_connections, content, filepath)
        
        return
    
    def _check_obfuscated_code(self, content, filepath):
        """Check for obfuscated code"""
        line_num = 1
        for line in content.split('\n'):
            for pattern in self.obfuscation_patterns:
                prog = re.compile(pattern)
                if prog.search(line) and not line.strip().startswith('#'):
                    self.results["obfuscated_code"].append({
                        "line": line_num,
                        "code": line.strip(),
                        "file": filepath,
                        "description": "Potentially obfuscated code"
                    })
            line_num += 1

    def _check_unauthorized_data_access(self, content, tree, filepath):
        """Check for unauthorized access to sensitive data or files"""
        line_num = 1
        for line in content.split('\n'):
            for pattern in self.sensitive_data_patterns:
                if re.search(pattern, line) and not line.strip().startswith('#'):
                    self.results["unauthorized_data_access"].append({
                        "line": line_num,
                        "code": line.strip(),
                        "file": filepath,
                        "description": "Access to sensitive system file or data"
                    })
            line_num += 1
        
        # walk ast and check for open() calls on suspicious paths     
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == 'open':
                if len(node.args) > 0 and isinstance(node.args[0], ast.Constant) and isinstance(node.args[0].value, str):
                    filepath_arg = node.args[0].value
                    if any(sensitive in filepath_arg for sensitive in self.suspicious_file_paths):
                        line_num = node.lineno
                        self.results["unauthorized_data_access"].append({
                            "line": line_num,
                            "code": self._get_line(content, line_num),
                            "file": filepath,
                            "description": f"Reading sensitive file: {filepath_arg}"
                        })
    
    def _check_unusual_imports(self, tree, filepath):
        """Check for unusual or suspicious module imports"""
        unusual_count = 0
        suspicious_imports = []
        
        for node in ast.walk(tree):
            # check for regular imports
            if isinstance(node, ast.Import):
                for name in node.names:
                    if name.name in self.unusual_imports:
                        unusual_count += 1
                        suspicious_imports.append(name.name)
                        line_num = node.lineno
                        self.results["unusual_imports"].append({
                            "line": line_num,
                            "code": f"import {name.name}",
                            "file": filepath,
                            "description": f"Unusual module import: {name.name}"
                        })
            
            # check from imports (from os import system)
            elif isinstance(node, ast.ImportFrom):
                if node.module in self.unusual_imports:
                    unusual_count += 1
                    suspicious_imports.append(node.module)
                    line_num = node.lineno
                    
                    # get the specific imports from the module
                    imported_names = [n.name for n in node.names]
                    self.results["unusual_imports"].append({
                        "line": line_num,
                        "code": f"from {node.module} import {', '.join(imported_names)}",
                        "file": filepath,
                        "description": f"Unusual module import: {node.module}"
                    })
        
        # add higher severity rating if multiple unusual imports
        if unusual_count >= 3:
            self.results["unusual_imports"].append({
                "line": 0,
                "code": f"Multiple unusual imports: {', '.join(suspicious_imports)}",
                "file": filepath,
                "description": f"High number of unusual/suspicious module imports ({unusual_count})"
            })
    
    def _check_suspicious_process_creation(self, tree, content, filepath):
        """Check for suspicious process creation or shell commands""" 
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                # check subprocess calls
                if isinstance(node.func, ast.Attribute) and hasattr(node.func, 'value'):
                    if isinstance(node.func.value, ast.Name) and node.func.value.id == 'subprocess' and node.func.attr in ['call', 'run', 'Popen']:
                        # check for suspicious commands
                        if len(node.args) > 0:
                            command = None
                            if isinstance(node.args[0], ast.Constant):
                                command = str(node.args[0].value)
                            elif isinstance(node.args[0], ast.List) and len(node.args[0].elts) > 0:
                                if isinstance(node.args[0].elts[0], ast.Constant):
                                    command = str(node.args[0].elts[0].value)
                            
                            if command and any(cmd in command for cmd in self.suspicious_commands):
                                line_num = node.lineno
                                self.results["suspicious_process_creation"].append({
                                    "line": line_num,
                                    "code": self.get_line(content, line_num),
                                    "file": filepath,
                                    "description": f"Suspicious command execution: {command}"
                                })
                # check os.system calls
                elif isinstance(node.func, ast.Attribute) and hasattr(node.func, 'value'):
                    if isinstance(node.func.value, ast.Name) and node.func.value.id == 'os' and node.func.attr == 'system':
                        if len(node.args) > 0 and isinstance(node.args[0], ast.Constant):
                            command = str(node.args[0].value)
                            if any(cmd in command for cmd in self.suspicious_commands):
                                line_num = node.lineno
                                self.results["suspicious_process_creation"].append({
                                    "line": line_num,
                                    "code": self._get_line(content, line_num),
                                    "file": filepath,
                                    "description": f"Suspicious os.system call: {command}"
                                })
    def _get_risk_level(self, score):
            """Convert numeric score to risk level"""
            if score == 0:
                return "Safe"
            elif score < 3:
                return "Low"
            elif score < 6:
                return "Medium"
            elif score < 8:
                return "High"
            else:
                return "Critical"
        
    def _check_hardcoded_credentials(self, content, filepath):
        """Check for hardcoded credentials"""        
        line_num = 1
        for line in content.split('\n'):
            for pattern in self.password_patterns:
                matches = re.search(pattern, line, re.IGNORECASE)
                if matches and not line.strip().startswith('#'):
                    self.results["hardcoded_credentials"].append({
                        "line": line_num,
                        "code": line.strip(),
                        "file": filepath
                    })
            line_num += 1

    def _check_command_injection(self, tree, content, filepath):
        """Check for command injection vulnerabilities"""
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                if isinstance(node.func, ast.Name) and node.func.id in ['system', 'popen', 'subprocess.call', 'subprocess.check_output']:
                    line_num = node.lineno
                    self.results["command_injection"].append({
                        "line": line_num,
                        "code": self._get_line(content, line_num),
                        "file": filepath
                    })
                elif isinstance(node.func, ast.Attribute) and node.func.attr in ['call', 'check_output', 'check_call', 'run']:
                    if hasattr(node.func, 'value') and isinstance(node.func.value, ast.Name) and node.func.value.id == 'subprocess':
                        for keyword in node.keywords:
                            if keyword.arg == 'shell' and isinstance(keyword.value, ast.Constant) and keyword.value.value == True:
                                line_num = node.lineno
                                self.results["command_injection"].append({
                                    "line": line_num,
                                    "code": self._get_line(content, line_num),
                                    "file": filepath
                                })

    def _check_insecure_deserialization(self, tree, content, filepath):
        """Check for insecure deserialization"""
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                if isinstance(node.func, ast.Attribute) and node.func.attr in ['loads'] and hasattr(node.func, 'value'):
                    if isinstance(node.func.value, ast.Name) and node.func.value.id in ['pickle', 'yaml']:
                        line_num = node.lineno
                        self.results["insecure_deserialization"].append({
                            "line": line_num,
                            "code": self._get_line(content, line_num),
                            "file": filepath
                        })

    def _check_sql_injection(self, content, filepath):
        """Check for SQL injection vulnerabilities"""
        sql_injection_patterns = [
            r"SELECT\s+.*\s+FROM\s+.*\s+WHERE\s+.*\s*=\s*'.*\{.*\}.*'",
            r"SELECT\s+.*\s+FROM\s+.*\s+WHERE\s+.*\s*=\s*\".*\{.*\}.*\"",
            r"execute\([\"'].*\{.*\}.*[\"']\)",
            r"query\s*=\s*f[\"']SELECT.*[\"']",
            r"query\s*=\s*f[\"']INSERT.*[\"']",
            r"query\s*=\s*f[\"']UPDATE.*[\"']",
            r"query\s*=\s*f[\"']DELETE.*[\"']"
        ]
        
        line_num = 1
        for line in content.split('\n'):
            for pattern in sql_injection_patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    self.results["sql_injection"].append({
                        "line": line_num,
                        "code": line.strip(),
                        "file": filepath
                    })
            line_num += 1

    def _check_path_traversal(self, tree, content, filepath):
        """Check for path traversal vulnerabilities"""
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == 'open':
                if len(node.args) > 0:
                    # Check if there's direct user input or concatenation without validation
                    if isinstance(node.args[0], ast.Name) or (isinstance(node.args[0], ast.BinOp) and not self._has_path_validation(content, node.lineno)):
                        line_num = node.lineno
                        self.results["path_traversal"].append({
                            "line": line_num,
                            "code": self._get_line(content, line_num),
                            "file": filepath
                        })

    def _has_path_validation(self, content, line_num):
        """Check if there's path validation before the specified line"""
        lines = content.split('\n')[:line_num]
        for line in reversed(lines):
            if re.search(r'os\.path\.normpath|os\.path\.abspath|\.startswith|\.endswith', line):
                return True
        return False

    def _check_insecure_ssl(self, tree, content, filepath):
        """Check for insecure SSL/TLS configuration"""
        for node in ast.walk(tree):
            # Check for SSL verification disabled
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == 'wrap_socket':
                for keyword in node.keywords:
                    if keyword.arg == 'cert_reqs' and isinstance(keyword.value, ast.Attribute) and keyword.value.attr == 'CERT_NONE':
                        line_num = node.lineno
                        self.results["insecure_ssl"].append({
                            "line": line_num,
                            "code": self._get_line(content, line_num),
                            "file": filepath
                        })
                        
            # Look for creation of insecure context
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == 'create_default_context':
                for attribute_setting in ast.walk(tree):
                    if isinstance(attribute_setting, ast.Assign) and isinstance(attribute_setting.targets[0], ast.Attribute):
                        target = attribute_setting.targets[0]
                        if target.attr in ['check_hostname', 'verify_mode'] and isinstance(attribute_setting.value, (ast.Constant, ast.NameConstant)) and not attribute_setting.value.value:
                            line_num = attribute_setting.lineno
                            self.results["insecure_ssl"].append({
                                "line": line_num,
                                "code": self._get_line(content, line_num),
                                "file": filepath
                            })

    def _check_exec_eval(self, tree, content, filepath):
        """Check for exec() or eval() usage"""
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id in ['exec', 'eval']:
                line_num = node.lineno
                self.results["exec_eval"].append({
                    "line": line_num,
                    "code": self._get_line(content, line_num),
                    "file": filepath
                })

    def _check_bind_all_interfaces(self, content, filepath):
        """Check for binding to all network interfaces"""
        bind_pattern = r"\.bind\s*\(\s*\(?['\"]0\.0\.0\.0['\"]\)?"
        line_num = 1
        for line in content.split('\n'):
            if re.search(bind_pattern, line):
                self.results["bind_all_interfaces"].append({
                    "line": line_num,
                    "code": line.strip(),
                    "file": filepath
                })
            line_num += 1

    def _check_insecure_file_operations(self, tree, content, filepath):
        """Check for insecure file operations"""
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == 'open':
                # Check if there's no validation before file operations
                context_lines = content.split('\n')[max(0, node.lineno-5):node.lineno]
                has_validation = any('os.path.exists' in line or 'os.path.isfile' in line for line in context_lines)
                
                if not has_validation:
                    line_num = node.lineno
                    self.results["insecure_file_operations"].append({
                        "line": line_num,
                        "code": self._get_line(content, line_num),
                        "file": filepath
                    })

    def _check_request_without_verification(self, content, filepath):
        """Check for HTTP requests with SSL verification disabled"""
        patterns = [
            r"requests\.(get|post|put|delete|patch)\(.*verify\s*=\s*False.*\)",
            r"urllib\.request\.urlopen\(.*context\s*=\s*.*\)"
        ]
        
        line_num = 1
        for line in content.split('\n'):
            for pattern in patterns:
                if re.search(pattern, line):
                    self.results["request_without_verification"].append({
                        "line": line_num,
                        "code": line.strip(),
                        "file": filepath
                    })
            line_num += 1

    def _get_line(self, content, line_num):
        """Get line by line number from content"""
        return content.split('\n')[line_num - 1].strip()

def generate_report(results, output_format="text"):
    """Generate a report of the vulnerability analysis"""
    if output_format == "text":
        report = []
        report.append("=" * 80)
        report.append("VULNERABILITY ANALYSIS REPORT")
        report.append("=" * 80)
        
        for file_result in results:
            report.append(f"\nFile: {file_result['filepath']}")
            report.append(f"Risk Score: {file_result['risk_score']}/10 ({file_result['risk_level']} Risk)")
            report.append("-" * 80)
            
            if 'error' in file_result:
                report.append(f"Error analyzing file: {file_result['error']}")
                continue
                
            if not file_result['vulnerabilities']:
                report.append("No vulnerabilities detected.")
                continue
                
            for vuln_type, occurrences in file_result['vulnerabilities'].items():
                report.append(f"\n[!] {vuln_type.replace('_', ' ').title()} ({len(occurrences)} occurrences)")
                for i, occurrence in enumerate(occurrences[:5], 1):  # Show at most 5 occurrences
                    report.append(f"  {i}. Line {occurrence['line']}: {occurrence['code']}")
                if len(occurrences) > 5:
                    report.append(f"  ... and {len(occurrences) - 5} more occurrences")
            
        return "\n".join(report)
    
    elif output_format == "json":
        import json
        return json.dumps(results, indent=2)
    
    else:
        return "Unsupported output format"

def scan_directory(directory, extensions=['.py']):
    """Recursively scan a directory for files with given extensions"""
    file_list = []
    for root, dirs, files in os.walk(directory):
        for file in files:
            if any(file.endswith(ext) for ext in extensions):
                file_list.append(os.path.join(root, file))
    return file_list


def main():
    parser = argparse.ArgumentParser(description='Analyze code for security vulnerabilities')
    parser.add_argument('target', help='File or directory to analyze')
    parser.add_argument('--format', choices=['text', 'json'], default='json', help='Output format')
    
    args = parser.parse_args()
    target = args.target
    
    analyzer = VulnerabilityAnalyzer()
    results = []
    
    if os.path.isfile(target):
        result = analyzer.analyze_file(target)
        results.append(result)
    elif os.path.isdir(target):
        files = scan_directory(target, ['.py'])
        print(f"Found {len(files)} Python files")
        for file in files:
            print(f"Analyzing {file}...")
            result = analyzer.analyze_file(file)
            results.append(result)
    else:
        print(f"Error: {target} is not a valid file or directory")
        return
    
    # Output all results, not just the first one
    if args.format == 'json':
        print(json.dumps(results, indent=2))
    else:
        print(generate_report(results, args.format))

    # parser = argparse.ArgumentParser(description='Analyze code for security vulnerabilities')
    # parser.add_argument('target', help='File or directory to analyze')
    # parser.add_argument('--format', choices=['text', 'json'], default='text', help='Output format')
    # parser.add_argument('--output', help='Output file (default: stdout)')
    # parser.add_argument('--extensions', default='.py', help='File extensions to analyze (comma-separated)')
    
    # args = parser.parse_args()
    # target = args.target
    # extensions = args.extensions.split(',')
    
    # analyzer = VulnerabilityAnalyzer()
    # results = []
    
    # if os.path.isfile(target):
    #     results.append(analyzer.analyze_file(target))
    # elif os.path.isdir(target):
    #     files = scan_directory(target, extensions)
    #     for file in files:
    #         print(f"Analyzing {file}...")
    #         results.append(analyzer.analyze_file(file))
    # else:
    #     print(f"Error: {target} is not a valid file or directory")
    #     return
    
    # report = generate_report(results, args.format)
    
    # if args.output:
    #     with open(args.output, 'w') as f:
    #         f.write(report)
    #     print(f"Report saved to {args.output}")
    # else:
    #     print(report)

if __name__ == "__main__":
    main()