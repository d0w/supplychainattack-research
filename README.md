# supplychainattack-research
Cybersecurity class project on mitigating supply chain attacks


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