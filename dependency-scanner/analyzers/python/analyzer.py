import os
import sys
import json
import subprocess
import re
import time
import urllib.request
import urllib.error
from pathlib import Path
from typing import Dict, Any, Optional
import math

# NVD API endpoint for CVE lookups
NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId="
# Rate limiting - NVD API limits to 5 requests per 30 seconds
NVD_RATE_LIMIT = 5
NVD_RATE_WINDOW = 30  # seconds
# Cache for NVD API results to avoid repeated lookups
nvd_cache = {}
# Keep track of API requests for rate limiting
api_request_times = []


def get_cve_data_from_nvd(cve_id: str) -> Optional[Dict[str, Any]]:
    """
    Get CVE data from the NVD API
    """
    global api_request_times

    # Return from cache if available
    if cve_id in nvd_cache:
        return nvd_cache[cve_id]

    # Implement rate limiting
    current_time = time.time()
    # Remove requests older than the rate window
    api_request_times = [
        t for t in api_request_times if current_time - t < NVD_RATE_WINDOW
    ]

    # Check if we're at the rate limit
    if len(api_request_times) >= NVD_RATE_LIMIT:
        # Wait until we can make another request
        oldest_request = min(api_request_times)
        wait_time = NVD_RATE_WINDOW - (current_time - oldest_request) + 1
        if wait_time > 0:
            print(
                f"Rate limiting: waiting {wait_time:.1f} seconds before next NVD API request",
                file=sys.stderr,
            )
            time.sleep(wait_time)

    # Make the API request
    url = f"{NVD_API_URL}{cve_id}"
    try:
        # Add User-Agent to avoid 403 errors
        req = urllib.request.Request(
            url, headers={"User-Agent": "PythonDependencyScanner/1.0"}
        )
        with urllib.request.urlopen(req) as response:
            # Record this request time for rate limiting
            api_request_times.append(time.time())

            data = json.loads(response.read().decode("utf-8"))

            # Check if we have valid CVE data
            if "vulnerabilities" in data and data["vulnerabilities"]:
                cve_data = data["vulnerabilities"][0]["cve"]
                nvd_cache[cve_id] = cve_data
                return cve_data
    # except urllib.error.HTTPError as e:
    #     print(
    #         f"HTTP error when accessing NVD API: {e.code} {e.reason}", file=sys.stderr
    #     )
    # except urllib.error.URLError as e:
    #     print(f"URL error when accessing NVD API: {e.reason}", file=sys.stderr)
    # except json.JSONDecodeError:
    #     print(f"Failed to parse NVD API response for {cve_id}", file=sys.stderr)
    except Exception as e:
        # print(f"Error accessing NVD API: {str(e)}", file=sys.stderr)
        pass

    # Cache the failure to avoid repeated lookups
    nvd_cache[cve_id] = None
    return None


def get_cvss_score(cve_id: str, default_score: float = 5.0) -> float:
    """
    Get CVSS score for a CVE from NVD

    """
    if not cve_id.startswith("CVE-"):
        return default_score

    cve_data = get_cve_data_from_nvd(cve_id)
    if not cve_data:
        return default_score

    # Try to get CVSS V3 score first, then CVSS V2 if V3 is not available
    try:
        # Look for CVSS V3 score
        metrics = cve_data.get("metrics", {})
        if "cvssMetricV31" in metrics:
            return metrics["cvssMetricV31"][0]["cvssData"]["baseScore"]
        elif "cvssMetricV30" in metrics:
            return metrics["cvssMetricV30"][0]["cvssData"]["baseScore"]
        elif "cvssMetricV2" in metrics:
            return metrics["cvssMetricV2"][0]["cvssData"]["baseScore"]
    except (KeyError, IndexError):
        pass

    return default_score


def severity_to_score(severity_str: str) -> int:
    """Convert severity string to numeric score"""
    severity_str = severity_str.lower()
    if severity_str == "critical":
        return 10
    elif severity_str == "high":
        return 8
    elif severity_str == "moderate" or severity_str == "medium":
        return 5
    elif severity_str == "low":
        return 3
    else:
        return 5  # Default to medium


def analyze_dependencies(requirements_path):
    """
    Analyze Python dependencies for security vulnerabilities using pip-audit

    Args:
        requirements_path: Path to requirements.txt or similar file

    Returns:
        Dict with analysis results
    """

    # Check if the file exists
    if not os.path.isfile(requirements_path):
        return {
            "file": requirements_path,
            "language": "python",
            "vulnerabilities": [],
            "risk_score": 0,
            "risk_level": "Error",
            "error": f"File does not exist: {requirements_path}",
        }

    # Try to install pip-audit if it's not already installed
    try:
        subprocess.run(
            ["pip", "show", "pip-audit"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=True,
        )
    except subprocess.CalledProcessError:
        return {
            "file": requirements_path,
            "language": "python",
            "vulnerabilities": [],
            "risk_score": 0,
            "risk_level": "Error",
            "error": "pip-audit is not installed. Please install it using 'pip install pip-audit'",
        }

    # Count dependencies in the requirements file
    dependencies = []
    try:
        with open(requirements_path, "r") as f:
            for line in f:
                line = line.strip()
                # Skip comments and empty lines
                if line and not line.startswith("#"):
                    # Extract package name (remove version specifiers)
                    package_match = re.match(r"^([a-zA-Z0-9_.-]+)", line)
                    if package_match:
                        dependencies.append(package_match.group(1))
    except Exception as e:
        return {
            "file": requirements_path,
            "language": "python",
            "vulnerabilities": [],
            "risk_score": 0,
            "risk_level": "Error",
            "error": f"Failed to parse requirements file: {str(e)}",
        }

    if not dependencies:
        return {
            "file": requirements_path,
            "language": "python",
            "vulnerabilities": [],
            "risk_score": 0,
            "risk_level": "Low",
            "message": "No dependencies found in requirements file",
        }

    # Run pip-audit on the requirements file
    try:
        # Run pip-audit with the requirements file
        # The --requirement flag takes the requirements file
        # The --format json outputs in JSON format
        cmd = ["pip-audit", "--requirement", requirements_path, "--format", "json"]

        result = subprocess.run(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True
        )

        # pip-audit returns 0 if no vulnerabilities found,
        # non-zero if vulnerabilities found or errors
        if result.returncode != 0 and not result.stdout:
            return {
                "file": requirements_path,
                "language": "python",
                "vulnerabilities": [],
                "risk_score": 0,
                "risk_level": "Error",
                "error": f"pip-audit check failed: {result.stderr}",
            }

        # Parse JSON output
        try:
            # If there's any output, try to parse it
            if result.stdout:
                pip_audit_result = json.loads(result.stdout)
                # print(json.dumps(pip_audit_result, indent=2))
            else:
                # No vulnerabilities found
                return {
                    "file": requirements_path,
                    "language": "python",
                    "vulnerabilities": [],
                    "risk_score": 0,
                    "risk_level": "Low",
                    "message": "No vulnerabilities found",
                }
        except json.JSONDecodeError:
            return {
                "file": requirements_path,
                "language": "python",
                "vulnerabilities": [],
                "risk_score": 0,
                "risk_level": "Error",
                "error": "Failed to parse pip-audit output",
            }

        # Transform pip-audit results to our vulnerability format
        vulnerabilities = {}
        total_severity = 0
        vuln_count = 0

        for vuln_entry in pip_audit_result.get("dependencies", []):
            # Each vulnerability has a package name and vulnerabilities list
            package_name = vuln_entry.get("name", "unknown")
            installed_version = vuln_entry.get("version", "unknown")

            for vulnerability in vuln_entry.get("vulns", []):
                vuln_id = vulnerability.get("id", "UNKNOWN")
                vuln_aliases = vulnerability.get("aliases", [])

                # Use the vuln_id as the vulnerability type key
                vuln_type = f"vulnerability_{vuln_id.replace('-', '_').lower()}"

                description = vulnerability.get(
                    "description", "No description available"
                )
                fixed_versions = vulnerability.get("fix_versions", [])
                fix_text = (
                    ", ".join(fixed_versions) if fixed_versions else "No fix available"
                )

                # Get severity from NVD if it's a CVE
                if vuln_aliases[0].startswith("CVE-"):
                    cvss_score = get_cvss_score(vuln_aliases[0])
                    severity = cvss_score
                else:
                    # Use pip-audit's severity if available, otherwise default
                    severity_str = vulnerability.get("severity", "")
                    severity = severity_to_score(severity_str)

                if vuln_type not in vulnerabilities:
                    vulnerabilities[vuln_type] = []

                vulnerabilities[vuln_type].append(
                    {
                        "line": 0,  # Not applicable for dependencies
                        "code": f"{package_name}@{installed_version}",
                        "severity": severity,
                        "type": vuln_aliases[0]
                        or vuln_id,  # Use the original ID as the type
                        "description": f"{description}. Fix: {fix_text}",
                    }
                )

                total_severity = max(total_severity, severity)

        # Determine risk level
        risk_level = get_risk_level(total_severity)

        return {
            "file": requirements_path,
            "language": "python",
            "vulnerabilities": [
                item for sublist in vulnerabilities.values() for item in sublist
            ],
            "risk_score": total_severity,
            "risk_level": risk_level,
            "dependency_count": len(dependencies),
        }

    except Exception as e:
        return {
            "file": requirements_path,
            "language": "python",
            "vulnerabilities": [],
            "risk_score": 0,
            "risk_level": "Error",
            "error": f"Error analyzing dependencies: {str(e)}",
        }


def get_risk_level(score):
    """Map a numeric score to a risk level"""
    if score >= 8:
        return "Critical"
    elif score >= 6:
        return "High"
    elif score >= 3:
        return "Medium"
    else:
        return "Low"


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Please provide a requirements.txt file path to analyze", file=sys.stderr)
        sys.exit(1)

    file_path = sys.argv[1]
    result = analyze_dependencies(file_path)

    # Print the result as JSON
    print(json.dumps(result, indent=2))
