package main

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"

	"github.com/d0w/supplychainattack-research/code-scanner/internal/reporter"
	"github.com/d0w/supplychainattack-research/code-scanner/internal/scanner"
	"github.com/spf13/cobra"
)

func main() {
	var (
		outputFormat string
		concurrency  int
		output       string
		analyzersDir string
		detailedInfo bool
	)

	// // Get default analyzers directory based on executable location
	// execPath, err := os.Executable()
	// if err != nil {
	//     fmt.Fprintf(os.Stderr, "Failed to determine executable path: %v\n", err)
	//     os.Exit(1)
	// }
	// defaultAnalyzersDir := filepath.Join(filepath.Dir(execPath), "analyzers")
	defaultAnalyzersDir, err := filepath.Abs("./analyzers")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to get absolute path for analyzers directory: %v\n", err)
		os.Exit(1)
	}

	rootCmd := &cobra.Command{
		Use:   "security-scanner [directory]",
		Short: "Scan code for security vulnerabilities",
		Long: `A security scanner that analyzes codebases for vulnerabilities across multiple programming languages,
providing a comprehensive risk assessment and detailed vulnerability reports.`,
		Args: cobra.MaximumNArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			// Determine directory to scan
			scanDir := "."
			if len(args) > 0 {
				scanDir = args[0]
			} else if len(args) < 1 {
				cmd.Help()
				os.Exit(0)
			}
			// Determine output writer
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

			// Create scanner and reporter
			secScanner := scanner.NewScanner(analyzersDir, concurrency)
			reporter := reporter.NewReporter(writer)

			// Run scan
			fmt.Fprintf(os.Stderr, "Scanning directory: %s\n", scanDir)
			result, issues, err := secScanner.ScanDirectory(scanDir)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Failed to scan directory: %v\n", err)
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

			if len(issues) > 0 {
				fmt.Println("======== Scan Issues ========")
				for _, issue := range issues {
					fmt.Fprintf(os.Stderr, "Issue: %s\n\n", issue)
				}
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

	// Define flags
	rootCmd.Flags().BoolVarP(&detailedInfo, "detailed", "d", false, "Show detailed information about vulnerabilities")
	rootCmd.Flags().StringVarP(&outputFormat, "format", "f", "text", "Output format (text, json)")
	rootCmd.Flags().IntVarP(&concurrency, "concurrency", "c", runtime.NumCPU(), "Number of concurrent file analyzers")
	rootCmd.Flags().StringVarP(&output, "output", "o", "", "Output file (default: stdout)")
	rootCmd.Flags().StringVarP(&analyzersDir, "analyzers-dir", "a", defaultAnalyzersDir, "Directory containing language analyzers")

	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}
