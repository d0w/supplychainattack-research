const fs = require('fs');
const path = require('path');
const acorn = require('acorn');
const walk = require('acorn-walk');

class VulnerabilityAnalyzer {
  constructor() {
    this.loadConfigurations()
  }

  getVulnerabilitySeverity(vulnType) {
    return this.vulnerabilityPatterns[vulnType]?.severity || 5;
  }


  /**
  * Load configurations for patterns, weights, and risk levels
  */
  loadConfigurations() {
    try {
      const metricsPath = path.join(__dirname, "../metrics.json");
      this.vulnerabilityPatterns = JSON.parse(fs.readFileSync(metricsPath, 'utf8'));

      const riskLevelsPath = path.join(__dirname, "../risk_levels.json");
      this.riskLevels = JSON.parse(fs.readFileSync(riskLevelsPath, 'utf8'));

      const patternsPath = path.join(__dirname, "../patterns.json");
      const patterns = JSON.parse(fs.readFileSync(patternsPath, 'utf8'));

      // use javscript patterns or none
      this.patterns = patterns.javascript;

      if (!this.patterns) {
        throw new Error("No JavaScript patterns found. Check the metrics files");
      }

      this.compiledPatterns = this.compileRegexPatterns();

      // console.log("Configuration files loaded successfully.");
    } catch (error) {
      // console.error(`Error loading config files: ${err.message}`);
      throw error;
    }
  }

  /**
   * Convert string patterns to regex objects
  */
  compileRegexPatterns() {
    const compiled = {};

    Object.keys(this.patterns).forEach(vulnType => {
      if (Array.isArray(this.patterns[vulnType])) {
        compiled[vulnType] = this.patterns[vulnType].map(pattern => {
          try {
            return new RegExp(pattern);
          } catch (err) {
            console.warn(`Invalid regex pattern for ${vulnType}: ${pattern}`);
            return null;
          }
        }).filter(pattern => pattern !== null);
      }
    });

    return compiled;
  }

  analyzeFile(filePath) {
    try {
      const content = fs.readFileSync(filePath, 'utf8');
      const results = {};

      // patern analysis
      this.performPatternAnalysis(content, results);

      // ast analysis
      this.performAstAnalysis(content, results);

      // calc risk score
      const riskScore = this.calculateRiskScore(results);

      let flattenedVulnerabilities = [];
      for (const [vulnType, vulnList] of Object.entries(results)) {
        if (vulnList.length > 0) {
          flattenedVulnerabilities = flattenedVulnerabilities.concat(vulnList);
        }
      }


      return {
        file: filePath,
        language: "javascript",
        vulnerabilities: flattenedVulnerabilities,
        risk_score: riskScore,
        risk_level: this.getRiskLevel(riskScore)
      };



    } catch (err) {
      // console.log(err)
      // console.error(`Error analyzing file ${filePath}: ${err.message}`);
      return {
        file: filePath,
        language: "javascript",
        error: err.message,
        risk_score: 0,
        risk_level: "Error"
      }
    }
  }

  performPatternAnalysis(content, results) {
    const lines = content.split("\n");
    this.checkPatterns(lines, this.compiledPatterns.password_patterns || [],
      'hardcoded_credentials', results, 'Hardcoded credentials found');

    // check for backdoor patterns
    this.checkPatterns(lines, this.compiledPatterns.backdoor_patterns || [],
      'backdoor', results, 'Potential backdoor pattern detected');

    // check for network patterns
    this.checkPatterns(lines, this.compiledPatterns.network_patterns || [],
      'suspicious_network_activity', results, 'Suspicious network activity detected');

    // check for obfuscated code
    this.checkPatterns(lines, this.compiledPatterns.obfuscation_patterns || [],
      'obfuscated_code', results, 'Potentially obfuscated code detected');

    // check for SQL injection
    this.checkPatterns(lines, this.compiledPatterns.sql_injection_patterns || [],
      'sql_injection', results, 'Possible SQL injection vulnerability');

    // check for XSS attacks
    this.checkPatterns(lines, this.compiledPatterns?.dom_xss_patterns || [],
      'command_injection', results, 'Possible DOM XSS vulnerability');
  }

  checkPatterns(lines, patterns, vulnType, results, description) {
    if (!patterns || patterns.length === 0) return;

    lines.forEach((line, index) => {
      if (line.trim().startsWith('//')) return; // skip comments

      patterns.forEach(pattern => {
        if (pattern.test(line)) {
          if (!results[vulnType]) {
            results[vulnType] = [];
          }

          results[vulnType].push({
            line: index + 1,
            code: line.trim(),
            severity: this.getVulnerabilitySeverity(vulnType),
            type: vulnType,
            description: description

          });
        }
      });
    });

  }

  performAstAnalysis(content, results) {
    try {
      const ast = acorn.parse(content, {
        ecmaVersion: 2022,
        sourceType: "module",
        locations: true
      });

      // check for DOM-based XSS vulnerabilities
      this.checkDomXss(ast, content, results);

      // check for dangerous eval/Function usage
      this.checkDangerousEval(ast, content, results);

      // check for insecure file operations
      this.checkInsecureFileOperations(ast, content, results);

      // check for command execution
      this.checkCommandExecution(ast, content, results);

      // check for network requests
      this.checkNetworkRequests(ast, content, results);

      // check for prototype pollution
      this.checkPrototypePollution(ast, content, results);

      // this.checkPrototypePollution(ast, content, results);

    } catch (err) {
      console.warn(`Ast parsing failed: ${err.message}`);
    }
  }

  checkDomXss(ast, content, results) {
    const lines = content.split("\n");

    walk.simple(ast, {
      AssignmentExpression(node) {
        if (node.left.type === "MemberExpression" && node.left.property.name === "innerHTML") {
          const lineNumber = node.loc.start.line;
          const lineContent = lines[lineNumber - 1].trim();

          if (!results.cross_site_scripting) {
            results.cross_site_scripting = [];
          }

          results.cross_site_scripting.push({
            line: lineNumber,
            code: lineContent,
            severity: this.getVulnerabilitySeverity('command_injection'),
            type: 'command_injection',
            description: 'Potential DOM XSS vulnerability'
          });
        }
      },

      CallExpression(node) {
        if (node.callee.type === "MemberExpression" && node.callee.object.name === "document" &&
          (node.callee.property.name === "write" || node.callee.property.name === "writeln")) {

          const lineNumber = node.loc.start.line;
          const lineContent = lines[lineNumber - 1].trim();

          if (!results.command_injection) {
            results.command_injection = [];
          }

          results.command_injection.push({
            line: lineNumber,
            code: lineContent,
            severity: this.getVulnerabilitySeverity("command_injection"),
            type: "command_injection",
            description: "Potential DOM XSS vulnerability"
          });

        }
      }
    })
  }

  checkDangerousEval(ast, content, results) {
    const lines = content.split("\n");

    walk.simple(ast, {
      CallExpression(node) {
        if (node.callee.type === "Identifier" && node.callee.name === "eval") {
          const lineNumber = node.loc.start.line;
          const lineContent = lines[lineNumber - 1].trim();

          if (!results.exec_eval) {
            results.exec_eval = [];
          }

          results.exec_eval.push({
            line: lineNumber,
            code: lineContent,
            severity: this.getVulnerabilitySeverity('exec_eval'),
            type: 'exec_eval',
            description: 'Dangerous eval usage detected'
          });
        }
      },

      NewExpression(node) {
        if (node.callee.type === 'Identifier' && node.callee.name === 'Function') {
          const lineNumber = node.loc.start.line;
          const lineContent = lines[lineNumber - 1].trim();

          if (!results.exec_eval) {
            results.exec_eval = [];
          }

          results.exec_eval.push({
            line: lineNumber,
            code: lineContent,
            severity: 10,
            type: 'exec_eval',
            description: 'Usage of new Function() - potential for code injection'
          });
        }
      }
    })
  }

  checkInsecureFileOperations(ast, content, results) {
    const lines = content.split('\n');

    const severity = this.getVulnerabilitySeverity('insecure_file_operations');

    walk.simple(ast, {
      CallExpression(node) {
        // Check for fs module usage
        if (node.callee.type === 'MemberExpression' &&
          node.callee.object.name === 'fs') {

          const dangerousMethods = ['readFile', 'writeFile', 'appendFile', 'readFileSync', 'writeFileSync'];

          if (dangerousMethods.includes(node.callee.property.name)) {
            // Check if path argument is user-controlled or includes variable without validation
            const lineNumber = node.loc.start.line;
            const lineContent = lines[lineNumber - 1].trim();

            // Check if path contains user input without validation
            const hasSanitization = lines.slice(Math.max(0, lineNumber - 5), lineNumber)
              .some(line => line.includes('path.normalize') || line.includes('path.resolve'));

            if (!hasSanitization) {
              if (!results.insecure_file_operations) {
                results.insecure_file_operations = [];
              }

              results.insecure_file_operations.push({
                line: lineNumber,
                code: lineContent,
                severity: severity,
                type: 'insecure_file_operations',
                description: 'File operation without path validation'
              });
            }
          }
        }
      }
    });
  }

  checkCommandExecution(ast, content, results) {
    const lines = content.split('\n');

    const severity = this.getVulnerabilitySeverity('command_execution');

    walk.simple(ast, {
      CallExpression(node) {
        if (node.callee.type === "MemberExpression") {
          const objectName = node.callee.object.name;
          const propertyName = node.callee.property.name;

          if (objectName === "child_process" || node.callee.object.name === "cp") {
            const dangerousMethods = ['exec', 'execFile', 'spawn', 'fork', "execSync", "spawnSync"];

            if (dangerousMethods.includes(node.callee.property.name)) {
              const lineNumber = node.loc.start.line;
              const lineContent = lines[lineNumber - 1].trim();

              if (!results.command_execution) {
                results.command_execution = [];
              }

              results.command_execution.push({
                line: lineNumber,
                code: lineContent,
                severity: severity,
                type: "command_execution",
                description: `Command execution with child_process.${node.callee.property.name} detected`
              });
            }
          }
          if ((node.callee.object.name === 'exec' ||
            node.callee.object.name === 'spawn') &&
            node.callee.property.name === 'call') {

            const lineNumber = node.loc.start.line;
            const lineContent = lines[lineNumber - 1].trim();

            if (!results[vulnType]) {
              results[vulnType] = [];
            }

            results[vulnType].push({
              line: lineNumber,
              code: lineContent,
              severity: 10,
              type: vulnType,
              description: `Command execution with ${node.callee.object.name}.call`
            });
          }
        }
      }
    });
  }

  checkNetworkRequests(ast, content, results) {
    const lines = content.split('\n');
    const vulnType = 'suspicious_network_activity';

    const severity = this.getVulnerabilitySeverity(vulnType);

    const networkModules = Object.keys(this.patterns.suspicious_network_funcs || {});

    walk.simple(ast, {
      CallExpression(node) {
        if (node.callee.type === 'MemberExpression') {
          const objName = node.callee.object.name;
          const propName = node.callee.property.name;

          // check for matching network module and method
          for (const module of networkModules) {
            if (objName === module &&
              this.patterns.suspicious_network_funcs[module].includes(propName)) {

              const lineNumber = node.loc.start.line;
              const lineContent = lines[lineNumber - 1].trim();

              if (!results[vulnType]) {
                results[vulnType] = [];
              }

              results[vulnType].push({
                line: lineNumber,
                code: lineContent,
                severity: severity,
                type: vulnType,
                description: `Suspicious network activity with ${objName}.${propName}`
              });

              break;
            }
          }

          // check for fetch API
          if (propName === 'fetch') {
            const lineNumber = node.loc.start.line;
            const lineContent = lines[lineNumber - 1].trim();

            if (!results[vulnType]) {
              results[vulnType] = [];
            }

            results[vulnType].push({
              line: lineNumber,
              code: lineContent,
              severity: severity,
              type: vulnType,
              description: 'Network request with fetch API'
            });
          }

          // check for XMLHttpRequest methods
          if (objName === 'xhr' || objName === 'ajax' || objName === 'request') {
            const lineNumber = node.loc.start.line;
            const lineContent = lines[lineNumber - 1].trim();

            if (!results[vulnType]) {
              results[vulnType] = [];
            }

            results[vulnType].push({
              line: lineNumber,
              code: lineContent,
              severity: severity,
              type: vulnType,
              description: `Network request with ${objName}.${propName}`
            });
          }
        }
      },

      NewExpression(node) {
        if (node.callee.type === 'Identifier' && node.callee.name === 'XMLHttpRequest') {
          const lineNumber = node.loc.start.line;
          const lineContent = lines[lineNumber - 1].trim();

          if (!results[vulnType]) {
            results[vulnType] = [];
          }

          results[vulnType].push({
            line: lineNumber,
            code: lineContent,
            severity: severity,
            type: vulnType,
            description: 'Network request with XMLHttpRequest'
          });
        }

        // check for WebSocket
        if (node.callee.type === 'Identifier' && node.callee.name === 'WebSocket') {
          const lineNumber = node.loc.start.line;
          const lineContent = lines[lineNumber - 1].trim();

          if (!results[vulnType]) {
            results[vulnType] = [];
          }

          results[vulnType].push({
            line: lineNumber,
            code: lineContent,
            severity: severity,
            type: vulnType,
            description: 'WebSocket connection'
          });
        }
      }
    }.bind(this));
  }

  

  calculateRiskScore(vulnerabilities) {
    if (!vulnerabilities || vulnerabilities.length === 0) return 0;

    let maxSeverity = 0;

    for (const [vulnType, vulnList] of Object.entries(vulnerabilities)) {
      if (vulnList.length > 0) {
        let severity = this.getVulnerabilitySeverity(vulnType);
        if (severity > maxSeverity) {
          maxSeverity = severity;
        }

        // weight repeats
        severity += Math.log10(vulnList.length) * 0.5;

        maxSeverity = Math.max(maxSeverity, severity);

      } else {
        continue;
      }

    }

    return Math.min(maxSeverity, 10);
  }

  getRiskLevel(riskScore) {
    for (const threshold of this.riskLevels?.risk_levels) {
      if (riskScore >= threshold.min && riskScore <= threshold.max) {
        return threshold.level;
      }
    }
    return this.riskLevels?.default_level;
  }

}


function main() {
  const args = process.argv.slice(2);

  if (args.length === 0) {
    console.error("No file path provided for analysis.");
    process.exit(1);
  }

  const filePath = args[0];
  const analyzer = new VulnerabilityAnalyzer();
  const results = analyzer.analyzeFile(filePath);
  console.log(JSON.stringify(results, null, 2));
}

if (require.main === module) {
  main();
}

module.exports = { analyzeFile: (filePath) => new VulnerabilityAnalyzer().analyzeFile(filePath) };
