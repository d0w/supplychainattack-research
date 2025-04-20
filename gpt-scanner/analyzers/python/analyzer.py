import ast
import os
import re
import argparse
import json
import logging
import sys
from collections import defaultdict
import math
from dotenv import load_dotenv
import openai
import tiktoken

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("gpt_analyzer_log.txt"),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger("GPTCodeAnalyzer")

class GPTAnalyzer:
    def __init__(self):
        # Load vulnerability patterns and their severities
        metrics_path = os.path.join(os.path.dirname(__file__), "../metrics.json")
        with open(metrics_path) as f:
            self.vulnerability_metrics = json.load(f)

        patterns_path = os.path.join(os.path.dirname(__file__), "../patterns.json")
        with open(patterns_path) as patterns_file:
            self.patterns = json.load(patterns_file)
        
        # Initialize OpenAI connection
        self.setup_openai()

    def setup_openai(self):
        """Set up the OpenAI API connection"""
        load_dotenv()
        api_key = os.environ.get("OPENAI_API_KEY")
        
        if not api_key:
            logger.error("OpenAI API key not found. Please add it to your .env file.")
            print("OpenAI API key not found. Please add it to your .env file.")
            sys.exit(1)
        
        try:
            openai.api_key = api_key
            # Test connection with a simple request
            response = openai.ChatCompletion.create(
                model="gpt-4",
                messages=[{"role": "user", "content": "Say hello"}],
                max_tokens=10
            )
            print("✓ OpenAI API connection successful")
            return True
        except Exception as e:
            logger.error(f"OpenAI API connection error: {e}")
            print(f"Error connecting to OpenAI API: {e}")
            sys.exit(1)

    def count_tokens(self, string, model="gpt-4"):
        """Returns the number of tokens in a text string"""
        try:
            encoding = tiktoken.encoding_for_model(model)
            num_tokens = len(encoding.encode(string))
            return num_tokens
        except Exception as e:
            logger.warning(f"Error counting tokens: {e}")
            # Rough estimate if tiktoken fails
            return len(string.split()) * 1.5

    def truncate_code_if_needed(self, code, max_tokens=8000):
        """Truncate code if it exceeds token limit"""
        current_tokens = self.count_tokens(code)
        
        if current_tokens <= max_tokens:
            return code
        
        # Split by lines
        lines = code.split('\n')
        
        # Calculate average tokens per line
        avg_tokens_per_line = current_tokens / len(lines)
        
        # Calculate how many lines we need to keep
        lines_to_keep = int(max_tokens / avg_tokens_per_line)
        
        # Keep some lines from the beginning and some from the end
        beginning_lines = int(lines_to_keep * 0.7)
        end_lines = lines_to_keep - beginning_lines
        
        truncated_code = '\n'.join(lines[:beginning_lines] + 
                                  ["# ... [code truncated due to length] ..."] + 
                                  lines[-end_lines:])
        
        return truncated_code

    def detect_language(self, filepath):
        """Detect the programming language of a file based on its extension"""
        ext = os.path.splitext(filepath)[1].lower()
        
        language_map = {
            '.py': 'python',
            '.js': 'javascript',
            '.ts': 'typescript',
            '.jsx': 'javascript',
            '.tsx': 'typescript',
            '.java': 'java',
            '.c': 'c',
            '.cpp': 'cpp',
            '.cs': 'csharp',
            '.php': 'php',
            '.rb': 'ruby',
            '.go': 'go',
            '.rs': 'rust',
            '.swift': 'swift',
            '.kt': 'kotlin',
            '.hs': 'haskell',
            '.sh': 'bash',
            '.html': 'html',
            '.css': 'css'
        }
        
        return language_map.get(ext, 'unknown')

    def get_patterns_for_language(self, language):
        """Get patterns specific to a language"""
        return self.patterns.get(language, {})

    def analyze_file_with_gpt(self, filepath):
        """Analyze a single file for vulnerabilities using GPT-4"""
        try:
            language = self.detect_language(filepath)
            
            if language == 'unknown':
                return {
                    "file": filepath,
                    "language": "unknown",
                    "error": "Unsupported file type",
                    "risk_score": 0,
                    "risk_level": "Unknown"
                }
            
            # Read file content
            with open(filepath, 'r', encoding='utf-8', errors='replace') as file:
                content = file.read()
            
            # Truncate if needed
            content = self.truncate_code_if_needed(content)
            
            # Get language patterns for prompt enhancement
            lang_patterns = self.get_patterns_for_language(language)
            
            # Prepare patterns for the prompt
            patterns_str = ""
            for category, pattern_list in lang_patterns.items():
                if isinstance(pattern_list, list) and len(pattern_list) > 0:
                    patterns_str += f"{category}:\n"
                    for i, pattern in enumerate(pattern_list[:3], 1):  # Limit to 3 examples per category
                        patterns_str += f"  {i}. {pattern}\n"
                    patterns_str += "\n"
            
            # Create prompt for GPT-4
            prompt = f"""You are a specialized code security analyzer. Analyze the following {language} code for security vulnerabilities, backdoors, and suspicious patterns.

Code to analyze:
```{language}
{content}
```

I want you to look for the following types of security issues:
1. Hardcoded credentials or API keys
2. Command injection vulnerabilities
3. Insecure deserialization
4. SQL injection
5. Path traversal
6. Insecure SSL/TLS configuration
7. Use of eval() or exec() on untrusted input
8. Binding to all network interfaces (0.0.0.0)
9. Insecure file operations
10. HTTP requests with SSL verification disabled
11. Potential backdoors
12. Suspicious network activity
13. Obfuscated or encoded code
14. Unauthorized access to sensitive data/files
15. Unusual imports
16. Suspicious process creation

Here are some examples of patterns to look for:
{patterns_str}

For each vulnerability found, provide:
1. The vulnerability type (from the list above)
2. The line number where it occurs
3. The specific code snippet
4. A description of the vulnerability
5. A severity rating from 1-10 (where 10 is most severe)

Then, provide an overall risk assessment from Low, Medium, High, to Critical, and a numerical risk score from 0-10.

Format your response in JSON with the following structure:
{{
  "vulnerabilities": [
    {{
      "type": "vulnerability_type",
      "line": line_number,
      "code": "suspicious_code_snippet",
      "description": "description_of_the_vulnerability",
      "severity": severity_rating
    }}
  ],
  "risk_score": numerical_score,
  "risk_level": "Low|Medium|High|Critical"
}}

DO NOT include any explanations outside the JSON. The JSON must be valid and properly formatted.
"""

            logger.info(f"Sending {filepath} to OpenAI for analysis...")
            
            # Call the OpenAI API
            response = openai.ChatCompletion.create(
                model="gpt-4",
                messages=[{"role": "user", "content": prompt}],
                temperature=0.1,  # Lower temperature for more consistent results
                max_tokens=4000
            )
            
            response_text = response.choices[0].message.content.strip()
            
            # Extract JSON from response (in case there's any surrounding text)
            json_match = re.search(r'({[\s\S]*})', response_text)
            if json_match:
                response_json = json.loads(json_match.group(1))
            else:
                response_json = json.loads(response_text)
            
            # Add file and language information
            response_json["file"] = filepath
            response_json["language"] = language
            
            return response_json
            
        except Exception as e:
            logger.error(f"Error analyzing {filepath}: {e}")
            return {
                "file": filepath,
                "language": self.detect_language(filepath),
                "error": str(e),
                "risk_score": 0,
                "risk_level": "Error"
            }

    def get_risk_level(self, score):
        """Convert numeric score to risk level"""
        risk_level_path = os.path.join(os.path.dirname(__file__), "../risk_levels.json")
        with open(risk_level_path) as f:
            risk_config = json.load(f)
        
        for level_info in risk_config["risk_levels"]:
            if level_info["min"] <= score <= level_info["max"]:
                return level_info["level"]
        return risk_config["default_level"]

def scan_directory(directory, extensions=None):
    """Recursively scan a directory for files with given extensions"""
    if extensions is None:
        extensions = ['.py', '.js', '.jsx', '.ts', '.tsx', '.java', '.php']
    
    file_list = []
    for root, dirs, files in os.walk(directory):
        for file in files:
            if any(file.endswith(ext) for ext in extensions):
                file_list.append(os.path.join(root, file))
    return file_list

def generate_text_report(results):
    """Generate a text report of the vulnerability analysis"""
    report = []
    report.append("=" * 80)
    report.append("GPT CODE ANALYSIS REPORT")
    report.append("=" * 80)

    for file_result in results:
        report.append(f"\nFile: {file_result['file']}")
        report.append(f"Language: {file_result['language']}")
        
        if 'error' in file_result:
            report.append(f"Error analyzing file: {file_result['error']}")
            continue
            
        report.append(f"Risk Score: {file_result['risk_score']}/10")
        report.append(f"Risk Level: {file_result['risk_level']}")
        report.append("-" * 80)
        
        if not file_result.get('vulnerabilities'):
            report.append("No vulnerabilities detected.")
            continue
            
        vulnerabilities = file_result['vulnerabilities']
        report.append(f"Found {len(vulnerabilities)} potential issue(s):")
        
        # Group vulnerabilities by type
        vuln_by_type = defaultdict(list)
        for vuln in vulnerabilities:
            vuln_by_type[vuln['type']].append(vuln)
        
        for vuln_type, occurrences in vuln_by_type.items():
            report.append(f"\n[!] {vuln_type.replace('_', ' ').title()} ({len(occurrences)} occurrences)")
            for i, occurrence in enumerate(occurrences[:5], 1):  # Show at most 5 occurrences
                severity_str = f"Severity: {occurrence['severity']}/10"
                report.append(f"  {i}. Line {occurrence['line']}: {occurrence['code']} [{severity_str}]")
                report.append(f"     {occurrence['description']}")
            
            if len(occurrences) > 5:
                report.append(f"  ... and {len(occurrences) - 5} more occurrences")
        
    return "\n".join(report)

def generate_json_report(results):
    """Generate a JSON report of the vulnerability analysis"""
    return json.dumps(results, indent=2)

def main():
    parser = argparse.ArgumentParser(description='Analyze code for security vulnerabilities using GPT')
    parser.add_argument('target', help='File or directory to analyze')
    parser.add_argument('--format', choices=['text', 'json'], default='text', help='Output format')
    parser.add_argument('--output', help='Output file (default: stdout)')
    parser.add_argument('--extensions', help='File extensions to analyze (comma-separated, default: py,js,jsx,ts,tsx,java,php)')
    
    args = parser.parse_args()
    target = args.target
    
    if args.extensions:
        extensions = args.extensions.split(',')
        # Add dot prefix if missing
        extensions = [ext if ext.startswith('.') else f'.{ext}' for ext in extensions]
    else:
        extensions = ['.py', '.js', '.jsx', '.ts', '.tsx', '.java', '.php']
    
    analyzer = GPTAnalyzer()
    results = []
    
    if os.path.isfile(target):
        print(f"Analyzing single file: {target}")
        results.append(analyzer.analyze_file_with_gpt(target))
    elif os.path.isdir(target):
        files = scan_directory(target, extensions)
        print(f"Found {len(files)} files to analyze")
        
        for i, file in enumerate(files, 1):
            print(f"Analyzing file {i}/{len(files)}: {file}")
            results.append(analyzer.analyze_file_with_gpt(file))
    else:
        print(f"Error: {target} is not a valid file or directory")
        return
    
    # Generate report
    if args.format == 'text':
        report = generate_text_report(results)
    else:
        report = generate_json_report(results)
    
    # Output report
    if args.output:
        with open(args.output, 'w') as f:
            f.write(report)
        print(f"Report saved to {args.output}")
    else:
        print(report)

if __name__ == "__main__":
    main()