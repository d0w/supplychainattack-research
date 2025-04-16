package detector

import (
	"os"
	"path/filepath"
	"strings"
)

// map languages to file extensions
var LanguageExtensionMap = map[string]string{
	".py": "python",
	".js": "javascript",
	// ".ts":   "typescript",
	".java":  "java",
	".rb":    "ruby",
	".php":   "php",
	".c":     "c",
	".cpp":   "cpp",
	".cs":    "csharp",
	".go":    "go",
	".rs":    "rust",
	".swift": "swift",
	".kt":    "kotlin",
	".sh":    "bash",
	".pl":    "perl",
	".r":     "r",
	".scala": "scala",
	".html":  "html",
	".css":   "css",
	".sql":   "sql",
}

var LanguageDependencyMap = map[string]string{
	"requirements.txt": "python",
	"package.json":     "javascript",
	"go.mod":           "go",
}

// determines language based on file extension
func DetectLanguage(filePath string) string {
	ext := strings.ToLower(filepath.Ext(filePath))
	if lang, ok := LanguageExtensionMap[ext]; ok {
		return lang
	}
	return "unknown"
}

// discovers all code files in directory
func FindCodeFiles(rootDir string) ([]string, error) {
	var files []string

	err := filepath.Walk(rootDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		// skip hidden files and directories
		if strings.HasPrefix(filepath.Base(path), ".") {
			if info.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}

		// // skip vendor directories and node_modules
		// if info.IsDir() && (filepath.Base(path) == "vendor" || filepath.Base(path) == "node_modules") {
		//     return filepath.SkipDir
		// }

		// Only process regular files
		if !info.IsDir() {
			ext := strings.ToLower(filepath.Ext(path))
			if _, ok := LanguageExtensionMap[ext]; ok {
				files = append(files, path)
			}
		}

		return nil
	})

	return files, err
}
