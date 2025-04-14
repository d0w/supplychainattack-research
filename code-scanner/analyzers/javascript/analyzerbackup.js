#!/usr/bin/env node
// filepath: /Users/derek/Documents/CSWork/EC521/supplychainattack-research/analyzers/javascript/analyzer.js

const fs = require('fs');
const path = require('path');
const acorn = require('acorn');
const walk = require('acorn-walk');

class VulnerabilityAnalyzer {
  constructor() {
    this.loadConfigurations()
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

      console.log("Configuration files loadd successfully.");
    } catch (error) {
      console.error(`Error loading config files: ${err.message}`);
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
      const fs = fs.readFileSync(filePath, 'utf8');
      const results = {};

      // patern analysis
      this.performPatternAnalysis(content, results);

      // ast analysis
      this.performASTAnalysis(content, results);

      // calc risk score
      const riskScore = this.calculateRiskScore(results);

      return {
        file: filePath,
        language: "javascript",
        vulnerabilities: results,
        risk_score: riskScore,
        risk_level: this.getRiskLevel(riskScore)
      };



    } catch (err) {
      console.error(`Error analyzing file ${filePath}: ${err.message}`);
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
      const ast = acron.parse(content, {
        ecmaVersion: 2022,
        sourceType: "module",
        locations: true
      });

      // dom xss
      this.checkDomXss(ast, content, results);
      this.checkDangerousEval(ast, content, results);
      this.checkInsecureFileOperations(ast, content, results);
      this.checkCommandExecution(ast, content, results);
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
      }
    })
  }

}

// Define vulnerability patterns
const filePath = path.join(__dirname, 'vulnerabilityPatterns.json');
const vulnerabilityPatterns = fs.readFile(filePath, "utf8", (err, data) => {
  if (err) throw err;
  return JSON.parse(data);
})

function analyzeFile(filePath) {
  try {
    const content = fs.readFileSync(filePath, 'utf8');
    const results = {};

    // regex analysis
    for (const [vulnType, config] of Object.entries(vulnerabilityPatterns)) {
      const occurrences = [];

      config.patterns.forEach(pattern => {
        const lines = content.split('\n');
        lines.forEach((line, index) => {
          if (pattern.test(line) && !line.trim().startsWith('//')) {
            occurrences.push({
              line: index + 1,
              code: line.trim(),
              file: filePath
            });
          }
        });
      });

      if (occurrences.length > 0) {
        results[vulnType] = occurrences;
        console.log(`Found ${occurrences.length} occurrences of ${vulnType} in ${filePath}`);
      }
    }

    // AST-based analysis (more complex vulnerabilities)
    try {
      const ast = acorn.parse(content, {
        ecmaVersion: 2022,
        sourceType: 'module',
        locations: true
      });

      // Example: Check for DOM XSS vulnerabilities
      walk.simple(ast, {
        AssignmentExpression(node) {
          if (node.left.type === 'MemberExpression' &&
            node.left.property.name === 'innerHTML') {
            const lineNumber = node.loc.start.line;
            const lineContent = content.split('\n')[lineNumber - 1].trim();

            if (!results.cross_site_scripting) {
              results.cross_site_scripting = [];
            }

            results.cross_site_scripting.push({
              line: lineNumber,
              code: lineContent,
              file: filePath
            });
          }
        }
      });

    } catch (e) {
      // AST parsing failed, continue with pattern-based results
    }

    // Calculate risk score
    const riskScore = calculateRiskScore(results);

    return {
      file: filePath,
      language: 'javascript',
      vulnerabilities: results,
      risk_score: riskScore,
      risk_level: getRiskLevel(riskScore)
    };

  } catch (error) {
    return {
      file: filePath,
      language: 'javascript',
      error: error.message,
      risk_score: 0,
      risk_level: 'Error'
    };
  }
}

function calculateRiskScore(vulnerabilities) {
  let totalSeverity = 0;
  let vulnerabilityCount = 0;

  for (const [vulnType, occurrences] of Object.entries(vulnerabilities)) {
    vulnerabilityCount += occurrences.length;
    const severity = vulnerabilityPatterns[vulnType]?.severity || 5;
    totalSeverity += occurrences.length * severity;
  }

  if (vulnerabilityCount === 0) return 0;

  const avgSeverity = totalSeverity / vulnerabilityCount;
  const countFactor = Math.min(1 + (vulnerabilityCount / 10), 2);

  return Math.min(Math.round(avgSeverity * countFactor * 10) / 10, 10);
}

function getRiskLevel(score) {
  if (score === 0) return 'Safe';
  if (score < 3) return 'Low';
  if (score < 6) return 'Medium';
  if (score < 8) return 'High';
  return 'Critical';
}

// Main execution
if (require.main === module) {
  const args = process.argv.slice(2);
  if (args.length === 0) {
    console.error('Please provide a file path to analyze');
    process.exit(1);
  }

  const filePath = args[0];
  const result = analyzeFile(filePath);
  console.log(JSON.stringify(result, null, 2));
}

module.exports = { analyzeFile };
