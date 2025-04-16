const fs = require('fs');
const path = require('path');
const { execSync } = require('child_process');

function getReport(auditResult, packageJsonPath) {
    // Transform npm audit results to our vulnerability format
    const vulnerabilities = {};
    let totalSeverity = 0;

    
    // Process vulnerabilities by type
    if (auditResult.vulnerabilities) {
      Object.values(auditResult.vulnerabilities).forEach(advisory => {
        const vulnType = advisory.name;
        
        if (!vulnerabilities[vulnType]) {
          vulnerabilities[vulnType] = [];
        }
        
        // Map severity to numeric score
        let severityScore;
        switch(advisory.severity) {
          case 'critical': severityScore = 10; break;
          case 'high': severityScore = 8; break;
          case 'moderate': severityScore = 5; break;
          case 'low': severityScore = 3; break;
          default: severityScore = 1;
        }
        
        totalSeverity = Math.max(totalSeverity, severityScore);

        let via = advisory.via.map(v => v.title || v).join(', ');
        let fixAvailable = advisory.fixAvailable ? `**Fix Available:** ${JSON.stringify(advisory.fixAvailable, undefined, 2)}` : '';
        
        // print via and fixAvailable
        let desc = `**Via:**\n${via}\n\n${fixAvailable}`;

        vulnerabilities[vulnType].push({
          line: 0, // Not applicable for dependencies
          code: `${advisory.name}@${advisory.range}`,
          severity: severityScore,
          type: vulnType,
          description: desc
        });
      });
    }
    
    // Calculate risk score based on vulnerabilities
    riskScore = Math.min(totalSeverity, 10);
    // Determine risk level
    let riskLevel;
    if (riskScore >= 8) riskLevel = "Critical";
    else if (riskScore >= 6) riskLevel = "High";
    else if (riskScore >= 3) riskLevel = "Medium";
    else riskLevel = "Low";

    // squish vulnerabilities into one array of all values
    const flatVulnerabilities = Object.values(vulnerabilities).flat();
    
    return {
      file: packageJsonPath,
      language: "javascript",
      vulnerabilities: flatVulnerabilities,
      risk_score: riskScore,
      risk_level: riskLevel
    };
}

/**
 * Analyzes JavaScript dependencies using npm audit
 */
function analyzeDependencies(packageJsonPath) {
  try {
    const packageDir = path.dirname(packageJsonPath);
    const packageJson = JSON.parse(fs.readFileSync(packageJsonPath, 'utf8'));
    
    // console.error(`Analyzing dependencies for: ${packageJsonPath}`);
    
    // Check if package.json exists and is valid
    if (!packageJson.dependencies && !packageJson.devDependencies) {
      return {
        file: packageJsonPath,
        language: "javascript",
        vulnerabilities: [],
        risk_score: 0,
        risk_level: "Low",
        message: "No dependencies found in package.json"
      };
    }

    // check if lock file exists
    const lockFilePath = path.join(packageDir, 'package-lock.json');
    if (!fs.existsSync(lockFilePath)) {
        return {
            file: packageJsonPath,
            language: "javascript",
            vulnerabilities: [],
            risk_score: 0,
            risk_level: "Low",
            message: "No dependencies found in package-lock.json. Make sure to npm install"
        };
    }
    
    try {
      // Run npm audit as JSON
      const auditOutput = execSync('npm audit --json', { 
        cwd: packageDir,
        encoding: 'utf8',
        stdio: ['pipe', 'pipe', 'pipe']
      });
      
      const auditResult = JSON.parse(auditOutput);

      const report = getReport(auditResult, packageJsonPath);
      return report;
      
      
      
    } catch (error) {
      // Handle npm audit errors
    //   console.log(error);
        if (error.stdout) {
            try {
                // Sometimes npm audit fails but still returns valid JSON
                const auditResult = JSON.parse(error.stdout.toString());

                const report = getReport(auditResult, packageJsonPath);
                return report;
            } catch (parseError) {
                // If we can't parse the output, return the error message
                // console.log(parseError)
                return {
                    file: packageJsonPath,
                    language: "javascript",
                    vulnerabilities: [],
                    risk_score: 0,
                    risk_level: "Error",
                    error: `npm audit error: ${error.message}`
                };
            }
        }
      
        return {
            file: packageJsonPath,
            language: "javascript",
            vulnerabilities: [],
            risk_score: 0,
            risk_level: "Error",
            error: `Failed to run npm audit: ${error.message}`
        };
    }
    
  } catch (error) {
    return {
      file: packageJsonPath,
      language: "javascript",
      vulnerabilities: [],
      risk_score: 0,
      risk_level: "Error",
      error: `Error analyzing dependencies: ${error.message}`
    };
  }
}

// Main execution
if (require.main === module) {
  const args = process.argv.slice(2);
  if (args.length === 0) {
    console.error('Please provide a package.json file path to analyze');
    process.exit(1);
  }
  
  const filePath = args[0];
  const result = analyzeDependencies(filePath);
  console.log(JSON.stringify(result, null, 2));
}

module.exports = { analyzeDependencies };