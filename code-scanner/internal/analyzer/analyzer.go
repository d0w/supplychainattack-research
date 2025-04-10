// internal/analyzer/analyzer.go
package analyzer

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sync"

	"github.com/d0w/supplychainattack-research/code-scanner/internal/models"
)

// Analyzer defines the interface for language-specific analyzers
type Analyzer interface {
	Analyze(filePath string) (*models.FileResult, error)
	SupportedLanguage() string
}

// maps language to analyzer
type Registry struct {
	analyzers map[string]Analyzer
	mutex     sync.RWMutex
}

// creates a new analyzer registry
func NewRegistry() *Registry {
	return &Registry{
		analyzers: make(map[string]Analyzer),
	}
}

// adds an analyzer to the registry
func (r *Registry) Register(analyzer Analyzer) {
	r.mutex.Lock()
	// run unlock after return
	defer r.mutex.Unlock()
	r.analyzers[analyzer.SupportedLanguage()] = analyzer
}

// returns the analyzer for a given language
func (r *Registry) GetAnalyzer(language string) (Analyzer, bool) {
	r.mutex.RLock()
	defer r.mutex.RUnlock()
	analyzer, ok := r.analyzers[language]
	return analyzer, ok
}

// implements the Analyzer interface for external analyzers
type ExternalAnalyzer struct {
	Language     string
	ScriptPath   string
	DefaultScore float64
}

// returns the language this analyzer supports
func (e *ExternalAnalyzer) SupportedLanguage() string {
	return e.Language
}

// runs the external analyzer script on the given file
func (e *ExternalAnalyzer) Analyze(filePath string) (*models.FileResult, error) {
	// fmt.Printf("Running external analyzer for %s on file: %s\n", e.Language, filePath)
	// check if script exists
	// print stats for debugging purposes

	if _, err := os.Stat(e.ScriptPath); os.IsNotExist(err) {
		fmt.Printf("Analyzer script does not exist: %s\n", e.ScriptPath)
		// if not exists, return a default "no vulnerabilities" result
		return &models.FileResult{
			File:            filePath,
			Language:        e.Language,
			Vulnerabilities: []models.Vulnerability{},
			RiskScore:       e.DefaultScore,
			RiskLevel:       models.CalculateRiskLevel(e.DefaultScore),
		}, nil
	}

	// get absolute path to the file
	absPath, err := filepath.Abs(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to get absolute path: %w", err)
	}

	var cmd *exec.Cmd
	// Run the external analyzer
	scriptExt := filepath.Ext(e.ScriptPath)

	// run appropriate command based on ext
	switch scriptExt {
	case ".py":
		cmd = exec.Command("python3", e.ScriptPath, absPath, "--format", "json") // for python scripts
	case ".js":
		cmd = exec.Command("node", e.ScriptPath, absPath) // for javascript (node) scripts
	case ".cpp", ".c":
		// compile binary then run

		// get dir name and base name of script
		scriptDir := filepath.Dir(e.ScriptPath)
		scriptBase := filepath.Base(e.ScriptPath)
		execName := scriptBase[:len(scriptBase)-len(filepath.Ext(scriptBase))] // remove extension for executable name

		// compile the C++ file to an executable
		// check if windows
		if os.PathSeparator == '\\' {
			execName += ".exe"
		}

		executablePath := filepath.Join(scriptDir, execName)

		compileNeeded := true
		if exeInfo, err := os.Stat(executablePath); err == nil {
			if srcInfo, err := os.Stat(e.ScriptPath); err == nil {
				// compile only if source is newer than executable
				compileNeeded = srcInfo.ModTime().After(exeInfo.ModTime())
			}
		}

		if compileNeeded {
			compileCmd := exec.Command("g++", "-o", executablePath, e.ScriptPath)
			cmd.Dir = scriptDir
			if err := compileCmd.Run(); err != nil {
				return nil, fmt.Errorf("failed to compile C++ analyzer: %w", err)
			}
		}

		cmd = exec.Command(executablePath, absPath)

	case ".go":
		// use go run
		cmd = exec.Command("go", "run", e.ScriptPath, absPath) // for Go scripts, use go run to execute the script directly
	default:
		cmd = exec.Command(e.ScriptPath, absPath)
	}

	// set the working directory to the file's directory
	cmd.Dir = filepath.Dir(absPath)

	// run command and get the output
	output, err := cmd.Output()
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			return nil, fmt.Errorf("analyzer failed: %s", exitErr.Stderr)
		}
		return nil, fmt.Errorf("failed to run analyzer: %w", err)
	}

	// print output
	// fmt.Printf("Analyzer output for %s on file %s: %s\n", e.Language, filePath, string(output))

	// parse output
	var result models.FileResult
	if err := json.Unmarshal(output, &result); err != nil {
		return nil, fmt.Errorf("failed to parse analyzer output: %w", err)
	}

	// set file path
	result.File = filePath
	result.Language = e.Language

	return &result, nil
}

// initializes a registry with all supported analyzers
func InitRegistry(analyzersDir string) *Registry {
	registry := NewRegistry()

	// external analyzers
	languages := map[string]string{
		"python":     filepath.Join("python", "analyzer.py"),
		"javascript": filepath.Join("javascript", "analyzer.js"),
		// "cpp": filepath.Join("cpp", "analyzer.cpp"), // example for C++ (if you have a C++ analyzer)
		// "go": filepath.Join("go", "analyzer.go"), // example for Go (if you have a Go analyzer)
		// "java": filepath.Join("java", "analyzer.java"), // example for Java (if you have a Java analyzer)
	}

	for lang, scriptPath := range languages {
		fullScriptPath := filepath.Join(analyzersDir, scriptPath)
		analyzer := &ExternalAnalyzer{
			Language:     lang,
			ScriptPath:   fullScriptPath,
			DefaultScore: 0.0, // default risk score when no vulnerabilities are found
		}
		registry.Register(analyzer)
	}

	return registry
}
