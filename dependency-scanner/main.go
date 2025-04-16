package main

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"

	"github.com/d0w/supplychainattack-research/dependency-scanner/internal/analyzer"
	"github.com/spf13/cobra"
)

func main() {
	var (
		outputFormat string
		concurrency  int
		output       string
		depLanguage  string
		detailedInfo bool
	)

	defaultAnalyzersDir, err := filepath.Abs("./analyzers")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to get absolute path for analyzers directory: %v\n", err)
		os.Exit(1)
	}
	rootCmd := &cobra.Command{
		Use:   "dependency-scanner [filepath]",
		Short: "Scan requirements files for security vulnerabilities",
		Long: `A security scanner that analyzes requirements files for vulnerabilities across multiple programming languages,
providing a risk assessment and detailed vulnerability reports.`,
		Args: cobra.MaximumNArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			// filepath of dependency file
			var filePath string

			if len(args) > 0 {
				filePath = args[0]
			} else {
				cmd.Help()
				os.Exit(0)
			}

			// determine writer
			var writer *os.File
			if output == "" || output == "-" {
				writer = os.Stdout
			} else {
				var err error
				writer, err = os.Create(output)
				if err != nil {
					fmt.Fprintf(os.Stderr, "failed to create output file: %v\n", err)
					os.Exit(1)
				}

				defer writer.Close()
			}

			// create scanner
			depScanner := analyzer.NewScanner(defaultAnalyzersDir, 1)
			reporter := analyzer.NewReporter(writer)

			fmt.Fprintf(os.Stdout, "Scanning file: %s\n", filePath)
			result, err := depScanner.ScanDepFile(filePath, depLanguage)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Failed to scan file: %v\n", err)
				os.Exit(1)
			}

			// Generate report
			var reportErr error
			switch outputFormat {
			case "json":
				reportErr = reporter.ReportJSON(result)
			case "text":
				reportErr = reporter.ReportText(result, detailedInfo)
			default:
				fmt.Fprintf(os.Stderr, "Unknown output format: %s\n", outputFormat)
				os.Exit(1)
			}

			if reportErr != nil {
				fmt.Fprintf(os.Stderr, "Failed to generate report: %v\n", reportErr)
				os.Exit(1)
			}

			// Exit with non-zero code if critical or high vulnerabilities were found
			if result.OverallLevel == "Critical" || result.OverallLevel == "High" {
				os.Exit(2)
			}
		},
	}

	rootCmd.Flags().BoolVarP(&detailedInfo, "detailed", "d", false, "Show detailed information about the scan")
	rootCmd.Flags().StringVarP(&outputFormat, "output-format", "f", "text", "Output format (json, xml, text)")
	rootCmd.Flags().IntVarP(&concurrency, "concurrency", "c", runtime.NumCPU(), "Number of concurrent workers")
	rootCmd.Flags().StringVarP(&output, "output", "o", "-", "Output file (default: stdout)")
	rootCmd.Flags().StringVarP(&depLanguage, "dep-language", "a", "", "Dependency file language")

	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error executing command: %v\n", err)
		os.Exit(1)
	}
}
