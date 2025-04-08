# user calls in their codebase, checks what the codebase language is, 
# then calls the appropriate scripts



import os
import json
import argparse
import subprocess
import concurrent.futures
from collections import defaultdict
from typing import Dict, List, Any
from tqdm import tqdm  # For progress bars



def detect_language(file_path: str) -> str:
    """Detects the programming language of a file based on its extension."""
    ext = os.path.splitext(file_path)[1].lower()

    if ext in [".py"]:
        return "python"
    elif ext in [".js", ".jsx", ".ts", ".tsx"]:
        return "javascript"
    elif ext in ["cpp"]:
        return "cpp"
    else:
        return "UNKNOWN"
    
def analyze_file(file_path: str) -> Dict[str, Any]:
    language = detect_language(file_path)

    if language == "UNKNOWN":
        return {
            "file": file_path,
            "language": "unknown",
            "error": "Unsupported file type",
            "risk_score": 0,
            "risk_level": "Unknown"
        }
    

    try:
        if language == 'python':
            return
            # return analyze_python_file(file_path)
        elif language == 'javascript':
            return
            # return analyze_javascript_file(file_path)
        elif language == 'java':
            return
            # return analyze_java_file(file_path)
            
        elif language == 'cpp':
            return
            # return analyze_cpp_file(file_path)
    except Exception as e:
        return {
            "file": file_path,
            "language": language,
            "error": str(e),
            "risk_score": 0,
            "risk_level": "Error"
        }
    
def analyze_python_file(file_path):
    "Run python analyzer in subprocess"
    try:
        # run python file
        return
    except Exception as e:
        result = subprocess.run(
            ["python", "./analyzers/python/analyzer.py"]
        )
    