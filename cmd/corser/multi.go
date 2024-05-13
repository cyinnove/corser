package main

import (
	"fmt"
	"os"
	"github.com/spf13/cobra"
	"github.com/zomasec/logz"
	"github.com/zomasec/corser/utils"
)

var (
	logger = logz.DefaultLogs()
)

func createMultiCmd(opts *options) *cobra.Command {
	var multiCmd = &cobra.Command{
		Use:   "multi",
		Short: "Performs scans on multiple URLs from a specified file or from standard input",
		Run: func(cmd *cobra.Command, args []string) {
			var urls []string
			if opts.file != "" {
				urls = utils.ReadFileLines(opts.file)
			} else {
				fmt.Println("Reading URLs from standard input. Enter URLs, one per line (Ctrl+D to end):")
				urls = utils.ReadURLsFromStdin()
			}
			if len(urls) == 0 {
				logger.ERROR("No URLs provided to scan.")
				os.Exit(1)
			}
			runScan(urls, opts)
		},
	}

	multiCmd.Flags().StringVarP(&opts.file, "list", "l", "", "Specifies a file path containing URLs to scan, with one URL per line. If omitted, URLs will be read from standard input.")
	multiCmd.Flags().StringVarP(&opts.outputFile, "output", "o", "", "Specifies the output file path where results should be saved.")

	return multiCmd
}

