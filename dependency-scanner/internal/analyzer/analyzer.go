package analyzer

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
)

// Analyzer defines the interface for language-specific analyzers
type Analyzer interface {
	Analyze(filePath string) (*FileResult, error)
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
func (e *ExternalAnalyzer) Analyze(filePath string) (*FileResult, error) {
	// get absolute path
	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		return nil, fmt.Errorf("file does not exist: %s", filePath)
	}

	absPath, err := filepath.Abs(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to get absolute path: %w", err)
	}

	var cmd *exec.Cmd

	// choose the right interpreter based on file extension
	scriptExt := filepath.Ext(e.ScriptPath)
	switch scriptExt {
	case ".js":
		cmd = exec.Command("node", e.ScriptPath, absPath)
	case ".py":
		cmd = exec.Command("python3", e.ScriptPath, absPath)
	default:
		// for executable scripts with no extension, assume they are directly executable
		cmd = exec.Command(e.ScriptPath, absPath)
	}

	// set working dir
	cmd.Dir = filepath.Dir(e.ScriptPath)

	// get output
	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("analyzer failed: %w\nOutput: %s", err, output)
	}

	// parse to JSON
	// fmt.Println(string(output))
	var result FileResult
	if err := json.Unmarshal(output, &result); err != nil {
		return nil, fmt.Errorf("failed to parse analyzer output: %w", err)
	}

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
