# supplychainattack-research

Cybersecurity class project on mitigating supply chain attacks.

This repository includes multiple tools (mostly CLI tools) that serve to help mitigate the risks or effects of supply chain attacks. Primarily, these tools will help with both contributors to a widely-used dependency, or for any downstream users of a dependency.

`code-scanner` is the static analysis tool that scans a directory, determines the file language, and runs the appropriate analysis script. This will output a list of vulnerabilities, their locations, and an overall risk score.

- This tool requires the source code of the dependency to be present, but can help with zero-day supply chain attacks.
- In theory, this tool can be used for environments such as open-source where, on a pull-request, a hook (such as a GitHub Action) is triggered, which will run this tool against the code that somebody is attempting to contribute. This will help catch any malicious code that is attempting to be injected into the codebase that may be used by many dependents.

`dependency-scanner` is the auditing tool that scans a dependency file (e.g. requirements.txt, package.json, etc.) and checks for known vulnerabilities. This will output a list of vulnerable dependencies and their locations.

- This does not require the source code of the dependency to be present, but does not help with zero-day supply chain attacks.
- In theory, this tool can be used by anyone who decides to install new dependencies, or needs to regularly check their existing ones. This can be binded to events such as pull requests, git commits, or simply when the dependency file is updated. This will help catch any malicious dependencies that have vulnerabilities that may unknown to or unwillingly installed by the user.
- This tool can also be used for typo-squatting attacks, where a malicious dependency is installed instead of the intended one. This can be done by checking the dependency file against a list of known malicious dependencies.

## Common output format

This is the common output format that all the analyzer scripts will output. Since these scripts are written in a variety of languages, they abide by this to abstract the language barrier. Behind the scenes, each script will write to STDOUT which gets piped into the Go module.

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

For the dependency-scanner, this format is maintained, but slightly modified

```json
{
  "file": "/path/to/requirements-file",
  "language": "language for requirements-file",
  "vulnerabilities": [
    {
      "type": "CVE or other identifier", 
      "severity": 9,
      "line": 0,
      "code": "dependency@version",
      "description": "Description given by CVE or other known database"
    }
  ],
  "risk_score": 7.5
}
```

# How to run

## Code Scanner

This is the tool to scan a directory statically. It requires the source code of the dependency to be present.

**Pre-requisites:**

- Go (1.24.2)
- Node.js (>=18.0)
- NPM
- Python (>=3.10)

1. Navigate to the `code-scanner/analyzers/javascript`
2. Run `npm install` to install the dependencies for the javascript analyzer
   - python analyzer does not require any additional dependencies currently

3. Run the `code-scanner` binary by navigating to the code-scanner directory and running `go run main.go /path/to/directory`
   - You can also run the binary directly by running `./code-scanner /path/to/directory`
   - Running `./code-scanner` without any arguments will print the usage instructions

## Dependency Scanner

This is the tool to scan a requirements file (requirements.txt, package.json are supported currently). All you need is the requirements file and the corresponding package manager listed in the pre-requisites.

**Pre-requisites**

- Go (1.24.2)
- Node.js (>=18.0)
- NPM
- Python (>=3.10)

1. Install `pip-audit` with `pip install pip-audit`.
   - You can opt to install this globally or in a virtual environment. The script will run the `pip-audit` as if it were in a shell, so make sure you can run `pip-audit` within your shell.

2. Navigate to the `dependency-scanner/` directory and run the binary either by `go run main.go /path/to/<requirements-file>` or `./dependency-scanner /path/to/requirements.txt`
   - Running the binary without any arguments will print the usage instructions

</br>

## GPT Scanner

This is the tool to scan a codebase and use openai's LLM to analyze the files and search for any supply chain vulnerabilities.

**Pre-requisites**
- openai 
- python-dotenv 
- tiktoken

1. Install the dependencies to run this analyzer
2. Run `python /path/to/analyzer /path/to/codebase`


# Code Scanner Process

One type of mitigation for supply chain attacks involves scanning code for any vulnerabilities. Whether this be run on dependencies or code that might be pushed to a repository that has many dependents, this can help mitigate some attacks against software supply chains.

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

Another possible method with static analysis over string matching and AST parsing is to leverage the power of LLMs. Using an LLM's reasoning capabilities, it can identify much more difficult or nuanced vulnerabilities. Though, this comes with the cost of speed and resources and thus is only used for files or directories specified by the user. Automatic parsing is only done with string and AST analysis.

## 3. Output Results

After analysis, a report is given with all the vulnerabilities(with their locations, code snippets, and severity), and an overall vulnerability score. This will give the user an informed decision if they wish to proceed with using dependencies or code based on how much they value security. This will also alert users to sudden changes in security if they installed poisoned dependencies, which could help mitigate the effects of a supply chain attack.

The risk score is calculated as follows

```math
\text{Risk Score} = \min\left(\max_{v \in V} \left( severity_v + log_{10}(count_v) \right), 10\right)
```

This is essentially finding the max severity vulnerability. Vulnerabilities with many repeats will be weighted higher with diminishing returns.

</br>

# Dependency Scanner Process

Unlike the code scanner, this relies on known vulnerabilities of dependencies, but does not need to statically analyze source code nor have source code to begin with. This helps with dependencies that might have been installed as binaries. As such, this does not prevent zero-day supply chain attacks, but it can help developers find out if they have outdated code with patched vulnerabilities.

## 1. Find Dependency File

The user gives a dependency file (e.g. requirements.txt, package.json, etc.). The module will attempt to parse the language that this file is for based on common semantics. If the file is not recognized, the user will be prompted to specify the language. The module will then run the appropriate analyzer script for that language.

## 2. Auditing

Typically, language-specific package managers have a built-in audit command. This will check the dependencies against known vulnerabilities and output a list of vulnerable dependencies. The module will run this command and parse the output to find the vulnerabilities. The Go module will call os.exec on the analyzer script, which then handles this auditing. This could also be done without a separate script, if the tools used are strictly CLI tools. We opted to stay with using external analyzer scripts, as it allows the usage of different auditing packages if necessary.

Some auditors might provide the CVE (common vulnerabilities and exposures) ID, which we then send to the NVD (National Vulnerability Database) to get more information (e.g. CVE Score) about the vulnerability. This will be used in conjunction with existing information to generate the vulnerability report.
