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
  "risk_score": 7.5
}
```

# Code Scanner Process
One type of mitigation for supply chain attacks involves scanning dependencies for any vulnerabilities. 

The code scanner tool is used to determine the vulnerability of a directory and outputting a list of problematic lines, the severity of code, and the type of vulnerability.

## 1. Scan File Tree
The Go module begins by scanning a directory and finding all files recursively. For each file, the module will determine the language of the file and then run the appropriate analysis script in a separate Goroutine. 

### 1.a Using Git Diffs
\<not implemented yet\>

Besides running analysis on an entire codebase which could be unneeded in many cases, one could specify two Git commits two check changes on. The idea of this is that when there are dependency updates or the like, the user can create a Git commit which would then be compared to the commit before changes. Only altered files are then fed to the analyzers  


## 2. Static Analysis
Static Analysis is run in two parts. Via string analysis and AST Analysis. String analysis is there to analyze simple patterns and helps when generating an AST is not arbitrary. The AST analysis gives a better understanding of code flow but not every language easily supports an AST.

Since the module runs on a variety of programming languages, there needs to be support for a variety of analyzers. To do this, we built a separate analyzer script for each language to support (`analyzer.js` for javascript, `analyzer.py` for python, etc.). This gives us native access to languages to perform tasks such as generate ASTs or even run dynamic analysis.

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

### 2.a LLM Analysis
\<Not yet implemented\>

Another possible method with static analysis over string matching and AST parsing is to leverage the power of LLMs. Using an LLM's reasoning capabilities, it can identify much more difficult or nuanced vulnerabilities. Though, this comes with the cost of speed and thus is only used for files or directories specified by the user. Automatic parsing is only done with string and AST analysis.

## 3. Output Results
After analysis, a report is given with all the vulnerabilities(with their locations, code snippets, and severity), and an overall vulnerability score. This will give the user an informed decision if they wish to proceed with using dependencies or code based on how much they value security. This will also alert users to sudden changes in security if they installed poisoned dependencies, which could help mitigate the effects of a supply chain attack.


