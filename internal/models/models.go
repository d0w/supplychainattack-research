package models

// Vulnerability represents a single security vulnerability found in code
type Vulnerability struct {
    Type        string  `json:"type"`
    Severity    float64 `json:"severity"`
    Line        int     `json:"line"`
    Code        string  `json:"code"`
    Description string  `json:"description"`
}

// FileResult represents scan results for a single file
type FileResult struct {
    File           string          `json:"file"`
    Language       string          `json:"language"`
    Vulnerabilities []Vulnerability `json:"vulnerabilities"`
    RiskScore      float64         `json:"risk_score"`
    RiskLevel      string          `json:"risk_level"`
}

// ScanResult represents the complete scan results for a codebase
type ScanResult struct {
    Files          []FileResult `json:"files"`
    TotalFiles     int          `json:"total_files"`
    FilesWithIssues int         `json:"files_with_issues"`
    TotalIssues    int          `json:"total_issues"`
    OverallScore   float64      `json:"overall_score"`
    OverallLevel   string       `json:"overall_level"`
}

// Risk levels
const (
    RiskLevelLow     = "Low"
    RiskLevelMedium  = "Medium"
    RiskLevelHigh    = "High"
    RiskLevelCritical = "Critical"
)

// CalculateRiskLevel converts a numerical score to a risk level string
func CalculateRiskLevel(score float64) string {
    switch {
    case score < 3.0:
        return RiskLevelLow
    case score < 6.0:
        return RiskLevelMedium
    case score < 8.5:
        return RiskLevelHigh
    default:
        return RiskLevelCritical
    }
}
