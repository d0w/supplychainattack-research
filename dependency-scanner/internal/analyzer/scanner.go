package analyzer

import (
	"fmt"
	"path/filepath"
)

type Scanner struct {
	AnalyzerRegistry *Registry
	AnalyzersDir     string
	Concurrency      int
}

func NewScanner(filePath string, concurrency int) *Scanner {
	if concurrency <= 0 {
		concurrency = 4 // default concurrency limit
	}

	return &Scanner{
		AnalyzerRegistry: InitRegistry(filePath),
		AnalyzersDir:     filePath,
		Concurrency:      concurrency,
	}
}

var LanguageMap = map[string]string{
	"requirements.txt": "python",
	"package.json":     "javascript",
	"go.mod":           "go",
}

// analyzes a requirements file
func (s *Scanner) ScanDepFile(filePath string, depLanguage string) (*ScanResult, error) {
	var language string

	// if depLanguage is not empty, use it
	if depLanguage != "" {
		language = depLanguage

		// if language not supported, return error
		isSupported := false

		for _, lang := range LanguageMap {
			if lang == language {
				isSupported = true
				break
			}
		}

		if !isSupported {
			return nil, fmt.Errorf("unsupported language: %s", language)
		}
	} else {
		language = DetectLanguage(filePath)
	}

	if language == "unknown" {
		return &ScanResult{
			// result in here
		}, nil
	}

	analyzer, ok := s.AnalyzerRegistry.GetAnalyzer(language)
	if !ok {
		return nil, fmt.Errorf("no analyzer available for language: %s", language)
	}

	analytics, err := analyzer.Analyze(filePath)
	if err != nil {
		return nil, fmt.Errorf("error analyzing file: %s", err)
	}

	fileResults := make([]FileResult, 1)
	fileResults[0] = *analytics

	filesWithIssues := 0
	if len(fileResults[0].Vulnerabilities) > 0 {
		filesWithIssues++
	}

	totalIssues := len(fileResults[0].Vulnerabilities)

	return &ScanResult{
		Files:           fileResults,
		TotalFiles:      1,
		FilesWithIssues: filesWithIssues,
		TotalIssues:     totalIssues,
		OverallScore:    fileResults[0].RiskScore,
		OverallLevel:    CalculateRiskLevel(fileResults[0].RiskScore),
	}, nil
}

func DetectLanguage(filePath string) string {
	// analyze the file to see what type it is

	filename := filepath.Base(filePath)
	if lang, ok := LanguageMap[filename]; ok {
		return lang
	}
	return "unknown"
}
