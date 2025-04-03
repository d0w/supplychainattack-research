# supplychainattack-research
Cybersecurity class project on mitigating supply chain attacks.

Program is written in multiple languages. Go is used as the primary bootstrapper that handles monitoring code changes and running routines. Inputted files are analyzed with a tool written in that respective language. For example, a Python file will be analyzed with `analyzer.py`.


## Common output format

```json
{
  "file": "/path/to/file",
  "language": "python",
  "vulnerabilities": [
    {
      "type": "sql_injection",
      "severity": 9,
      "line": 42,
      "code": "query = f\"SELECT * FROM users WHERE id = '{user_id}'\"",
      "description": "Possible SQL injection vulnerability"
    }
  ],
  "risk_score": 7.5,
  "risk_level": "High"
}
```

## Analysis
Two parts
**Regex (String) Analysis:**

Catches textual patterns that might be missed by AST parsing
Works even if the code has syntax errors
Can detect patterns that span multiple statements
Better at finding obfuscated code


**AST Analysis:**

Understands the structure of the code
Avoids false positives in comments and strings
Can analyze complex relationships between nodes
Better for understanding context