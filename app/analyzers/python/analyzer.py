#!/usr/bin/env python3
# filepath: /Users/derek/Documents/CSWork/EC521/supplychainattack-research/vulnerability_analyzer.py

import ast
import os
import re
import argparse
from collections import defaultdict

class VulnerabilityAnalyzer:
    def __init__(self):
        # Define vulnerability patterns with severity weights (1-10)
        self.vulnerability_patterns = {
            "hardcoded_credentials": {
                "severity": 9,
                "description": "Hardcoded credentials or API keys in code"
            },
            "command_injection": {
                "severity": 10,
                "description": "Possible command injection vulnerability"
            },
            "insecure_deserialization": {
                "severity": 8,
                "description": "Unsafe deserialization of user input"
            },
            "sql_injection": {
                "severity": 9,
                "description": "Possible SQL injection vulnerability"
            },
            "path_traversal": {
                "severity": 7,
                "description": "Path traversal vulnerability"
            },
            "insecure_ssl": {
                "severity": 6,
                "description": "Insecure SSL/TLS configuration"
            },
            "exec_eval": {
                "severity": 10,
                "description": "Use of exec() or eval() on untrusted input"
            },
            "bind_all_interfaces": {
                "severity": 5,
                "description": "Binding to all network interfaces (0.0.0.0)"
            },
            "insecure_file_operations": {
                "severity": 6,
                "description": "Insecure file operations without validation"
            },
            "request_without_verification": {
                "severity": 5,
                "description": "HTTP requests with SSL verification disabled"
            }
        }
        
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
            
            # Calculate risk score
            score = self._calculate_risk_score()
            
            return {
                "filepath": filepath,
                "vulnerabilities": dict(self.results),
                "risk_score": score,
                "risk_level": self._get_risk_level(score)
            }
            
        except Exception as e:
            return {
                "filepath": filepath,
                "error": str(e),
                "risk_score": 0,
                "risk_level": "Error"
            }
    
    def _calculate_risk_score(self):
        """Calculate risk score based on vulnerabilities found"""
        if not self.results:
            return 0
            
        total_severity = 0
        vulnerability_count = 0
        
        for vuln_type, occurrences in self.results.items():
            vulnerability_count += len(occurrences)
            total_severity += len(occurrences) * self.vulnerability_patterns[vuln_type]["severity"]
        
        # Base score on average severity and count
        if vulnerability_count == 0:
            return 0
            
        avg_severity = total_severity / vulnerability_count
        # Scale based on number of findings
        count_factor = min(1 + (vulnerability_count / 10), 2)  # Cap at 2x multiplier
        
        return min(round(avg_severity * count_factor, 1), 10)  # Cap at 10
        
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
        # Look for password patterns
        password_patterns = [
            r'password\s*=\s*["\'](?!.*\$\{)(\w+)["\']',
            r'passwd\s*=\s*["\'](?!.*\$\{)(\w+)["\']',
            r'api_key\s*=\s*["\'](?!.*\$\{)(\w+)["\']',
            r'secret\s*=\s*["\'](?!.*\$\{)(\w+)["\']',
            r'token\s*=\s*["\'](?!.*\$\{)(\w+)["\']'
        ]
        
        line_num = 1
        for line in content.split('\n'):
            for pattern in password_patterns:
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
                        # Check if shell=True is used
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
    parser.add_argument('--format', choices=['text', 'json'], default='text', help='Output format')
    parser.add_argument('--output', help='Output file (default: stdout)')
    parser.add_argument('--extensions', default='.py', help='File extensions to analyze (comma-separated)')
    
    args = parser.parse_args()
    target = args.target
    extensions = args.extensions.split(',')
    
    analyzer = VulnerabilityAnalyzer()
    results = []
    
    if os.path.isfile(target):
        results.append(analyzer.analyze_file(target))
    elif os.path.isdir(target):
        files = scan_directory(target, extensions)
        for file in files:
            print(f"Analyzing {file}...")
            results.append(analyzer.analyze_file(file))
    else:
        print(f"Error: {target} is not a valid file or directory")
        return
    
    report = generate_report(results, args.format)
    
    if args.output:
        with open(args.output, 'w') as f:
            f.write(report)
        print(f"Report saved to {args.output}")
    else:
        print(report)

if __name__ == "__main__":
    main()