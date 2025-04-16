package analyzer

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"text/tabwriter"
	"unicode/utf8"

	"github.com/fatih/color"
)

// Reporter formats and outputs scan results
type Reporter struct {
	writer io.Writer
}

// NewReporter creates a new reporter
func NewReporter(writer io.Writer) *Reporter {
	if writer == nil {
		writer = os.Stdout
	}
	return &Reporter{writer: writer}
}

// ReportJSON outputs the scan results as JSON
func (r *Reporter) ReportJSON(result *ScanResult) error {
	encoder := json.NewEncoder(r.writer)
	encoder.SetIndent("", "  ")
	return encoder.Encode(result)
}

// ReportText outputs the scan results as formatted text
func (r *Reporter) ReportText(result *ScanResult, detailed bool) error {
	w := tabwriter.NewWriter(r.writer, 0, 0, 2, ' ', 0)

	// Sort files by risk score (highest first)
	sortedFiles := make([]FileResult, len(result.Files))
	copy(sortedFiles, result.Files)
	sort.Slice(sortedFiles, func(i, j int) bool {
		return sortedFiles[i].RiskScore > sortedFiles[j].RiskScore
	})

	// List vulnerable files
	if result.FilesWithIssues > 0 {
		fmt.Fprintln(w, "===== Vulnerable Files =====")
		fmt.Fprintln(w, "File\tLanguage\tIssues\tRisk Score\tRisk Level")
		fmt.Fprintln(w, "----\t--------\t------\t----------\t----------")

		for _, file := range sortedFiles {
			if len(file.Vulnerabilities) > 0 {

				riskColor := colorForRiskLevel(file.RiskLevel)
				fmt.Fprintf(w, "%s\t%s\t%d\t%.1f\t%s\n",
					file.File, file.Language, len(file.Vulnerabilities),
					file.RiskScore, riskColor(file.RiskLevel))

			}
		}
		fmt.Fprintln(w)

		// if detailed is not true, return here
		// if !detailed {
		// 	return w.Flush()
		// }

		// List vulnerabilities by file
		fmt.Fprintln(w, "===== Detailed Vulnerabilities =====")
		for _, file := range sortedFiles {
			if len(file.Vulnerabilities) > 0 {
				fmt.Fprintf(w, "File: %s (%s)\n", file.File, file.Language)

				vulnTableWriter := tabwriter.NewWriter(w, 16, 8, 2, ' ', 0)

				fmt.Fprintln(vulnTableWriter, "Dependency\tType\tSeverity")
				fmt.Fprintln(vulnTableWriter, "----------\t----\t--------")

				// Sort vulnerabilities by severity (highest first)
				sort.Slice(file.Vulnerabilities, func(i, j int) bool {
					return file.Vulnerabilities[i].Severity > file.Vulnerabilities[j].Severity
				})

				for _, vuln := range file.Vulnerabilities {
					sevColor := colorForSeverity(vuln.Severity)
					sevText := fmt.Sprintf("%.1f", vuln.Severity)

					fmt.Fprintf(vulnTableWriter, "%s\t%s\t%s\n",
						vuln.Code,
						vuln.Type,
						sevColor(sevText),
					)

				}
				vulnTableWriter.Flush()

				if !detailed {
					continue
				}

				// Print descriptions separately with text wrapping
				fmt.Fprintln(r.writer, "\nDescription:")
				fmt.Fprintln(r.writer, "------------")

				for _, vuln := range file.Vulnerabilities {
					fmt.Fprintf(r.writer, "- %s: ", vuln.Type)

					// Print the wrapped description
					wrapped := wrapText(vuln.Description, 70, len(vuln.Type)+4)
					fmt.Fprintln(r.writer, wrapped)
					fmt.Fprintln(r.writer)
				}

				fmt.Fprintln(r.writer, strings.Repeat("-", 70))
				fmt.Fprintln(r.writer)

			}
		}
	} else {
		fmt.Fprintln(w, "No vulnerabilities detected.")
	}

	// Overall summary
	fmt.Fprintln(w, "===== Security Scan Summary =====")
	fmt.Fprintf(w, "Files Scanned:\t%d\n", result.TotalFiles)
	fmt.Fprintf(w, "Files With Issues:\t%d\n", result.FilesWithIssues)
	fmt.Fprintf(w, "Total Issues:\t%d\n", result.TotalIssues)

	// Color-coded overall risk
	overallRiskColor := colorForRiskLevel(result.OverallLevel)
	fmt.Fprintf(w, "Overall Risk:\t%s (%.1f)\n\n",
		overallRiskColor(result.OverallLevel), result.OverallScore)

	return w.Flush()
}

// Helper functions to color output based on risk/severity
func colorForRiskLevel(level string) func(a ...interface{}) string {
	switch level {
	case RiskLevelCritical:
		return color.New(color.FgHiRed, color.Bold).SprintFunc()
	case RiskLevelHigh:
		return color.New(color.FgRed).SprintFunc()
	case RiskLevelMedium:
		return color.New(color.FgYellow).SprintFunc()
	default:
		return color.New(color.FgGreen).SprintFunc()
	}
}

func colorForSeverity(severity float64) func(a ...interface{}) string {
	switch {
	case severity >= 8.5:
		return color.New(color.FgHiRed, color.Bold).SprintFunc()
	case severity >= 6.0:
		return color.New(color.FgRed).SprintFunc()
	case severity >= 3.0:
		return color.New(color.FgYellow).SprintFunc()
	default:
		return color.New(color.FgGreen).SprintFunc()
	}
}

// wrapText wraps a long text to fit within maxWidth, with subsequent lines indented
func wrapText(text string, maxWidth, indent int) string {
	if maxWidth <= 0 || len(text) <= maxWidth {
		return text
	}

	var result strings.Builder
	indentStr := strings.Repeat(" ", indent)
	lineStart := 0
	lineWidth := 0
	isFirstLine := true

	for i, r := range text {
		charWidth := utf8.RuneLen(r)

		// Check if adding this character would exceed max width
		if lineWidth+charWidth > maxWidth && i > lineStart {
			// Write the current line
			if isFirstLine {
				result.WriteString(text[lineStart:i])
				isFirstLine = false
			} else {
				result.WriteString(indentStr + text[lineStart:i])
			}
			result.WriteRune('\n')
			lineStart = i
			lineWidth = charWidth
		} else {
			lineWidth += charWidth
		}

		// Handle newlines in the original text
		if r == '\n' {
			if isFirstLine {
				result.WriteString(text[lineStart:i])
				isFirstLine = false
			} else {
				result.WriteString(indentStr + text[lineStart:i])
			}
			result.WriteRune('\n')
			lineStart = i + 1
			lineWidth = 0
		}
	}

	// Add the last line
	if lineStart < len(text) {
		if isFirstLine {
			result.WriteString(text[lineStart:])
		} else {
			result.WriteString(indentStr + text[lineStart:])
		}
	}

	return result.String()
}
