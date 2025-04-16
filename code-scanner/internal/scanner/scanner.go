package scanner

import (
	"fmt"
	// "path/filepath"
	"sync"

	"github.com/d0w/supplychainattack-research/code-scanner/internal/analyzer"
	"github.com/d0w/supplychainattack-research/code-scanner/internal/detector"
	"github.com/d0w/supplychainattack-research/code-scanner/internal/models"
)

type Scanner struct {
	AnalyzerRegistry *analyzer.Registry
	AnalyzersDir     string
	Concurrency      int
}

// create scanner instance
func NewScanner(analyzersDir string, concurrency int) *Scanner {
	if concurrency <= 0 {
		concurrency = 4 // default concurrency limit
	}

	return &Scanner{
		AnalyzerRegistry: analyzer.InitRegistry(analyzersDir),
		AnalyzersDir:     analyzersDir,
		Concurrency:      concurrency,
	}
}

// analyzes a single file for vulnerabilities
func (s *Scanner) ScanFile(filePath string) (*models.FileResult, error) {
	// detect language
	language := detector.DetectLanguage(filePath)
	if language == "unknown" {
		return &models.FileResult{
			File:            filePath,
			Language:        "unknown",
			Vulnerabilities: []models.Vulnerability{},
			RiskScore:       0,
			RiskLevel:       models.RiskLevelLow,
		}, nil
	}

	// get appropriate analyzer script
	analyzer, ok := s.AnalyzerRegistry.GetAnalyzer(language)
	if !ok {
		return nil, fmt.Errorf("no analyzer available for language: %s", language)
	}

	// analyze the file
	return analyzer.Analyze(filePath)
}

// scans an entire directory
// returns scan result, any issues, and error if any
func (s *Scanner) ScanDirectory(rootDir string) (*models.ScanResult, []error, error) {
	// Find all code files
	files, err := detector.FindCodeFiles(rootDir)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to find code files: %w", err)
	}

	// set up concurrency control
	var wg sync.WaitGroup                                    // tracks when goroutines complete
	semaphore := make(chan struct{}, s.Concurrency)          // limits concurrent executions
	resultsChan := make(chan *models.FileResult, len(files)) // channel to collect results
	errorsChan := make(chan error, len(files))               // channel to collect errors

	// process each file concurrently
	for _, file := range files {
		// add file to wait group
		wg.Add(1)
		// launch a goroutine to process the file
		go func(filePath string) {
			defer wg.Done()
			semaphore <- struct{}{}        // acquire sem. blocks if the semaphore is full
			defer func() { <-semaphore }() // release sem

			result, err := s.ScanFile(filePath)
			if err != nil {
				errorsChan <- fmt.Errorf("error scanning %s: %w", filePath, err)
				return
			}
			resultsChan <- result
		}(file)
	}

	// wait for all goroutines to complete
	wg.Wait()
	close(resultsChan)
	close(errorsChan)

	// collect errors
	var errors []error
	for err := range errorsChan {
		errors = append(errors, err)
	}

	// if errors, return the first one encountered
	// if len(errors) > 0 {
	//     return nil, errors[0]
	// }

	// collect results
	var fileResults []models.FileResult
	var overallScore float64
	var totalIssues int
	var filesWithIssues int

	for result := range resultsChan {
		fileResults = append(fileResults, *result)
		totalIssues += len(result.Vulnerabilities)
		if len(result.Vulnerabilities) > 0 {
			filesWithIssues++
		}
		overallScore = max(overallScore, result.RiskScore)
	}

	// Create final result
	scanResult := &models.ScanResult{
		Files:           fileResults,
		TotalFiles:      len(fileResults),
		FilesWithIssues: filesWithIssues,
		TotalIssues:     totalIssues,
		OverallScore:    overallScore,
		OverallLevel:    models.CalculateRiskLevel(overallScore),
	}

	// return errors if any, else return nil

	if len(errors) > 0 {
		return scanResult, errors, nil
	}
	return scanResult, nil, nil
}
