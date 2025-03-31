#!/usr/bin/env node
// filepath: /Users/derek/Documents/CSWork/EC521/supplychainattack-research/analyzers/javascript/analyzer.js

const fs = require('fs');
const path = require('path');
const acorn = require('acorn');
const walk = require('acorn-walk');

// Define vulnerability patterns
const vulnerabilityPatterns = {
  hardcoded_credentials: {
    severity: 9,
    patterns: [
      /password\s*[:=]\s*['"](?!.*\$\{)(\w+)['"]/i,
      /apiKey\s*[:=]\s*['"](?!.*\$\{)(\w+)['"]/i,
      /secret\s*[:=]\s*['"](?!.*\$\{)(\w+)['"]/i,
      /token\s*[:=]\s*['"](?!.*\$\{)(\w+)['"]/i
    ]
  },
  command_injection: {
    severity: 10,
    patterns: [
      /exec\(.*\)/,
      /execSync\(.*\)/,
      /spawn\(.*\)/,
      /child_process/,
      /eval\(/
    ]
  },
  // Add more pattern definitions...
};

function analyzeFile(filePath) {
  try {
    const content = fs.readFileSync(filePath, 'utf8');
    const results = {};
    
    // Pattern-based analysis
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