package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"github.com/zomasec/corser/pkg/config"
	"github.com/zomasec/corser/pkg/utils"
	"github.com/zomasec/logz"
)

var (
	logger = logz.DefaultLogs()
)

func createMultiCmd(options *config.Options) *cobra.Command {
	var multiCmd = &cobra.Command{
		Use:   "multi",
		Short: "Performs scans on multiple URLs from a specified file or from standard input",
		Run: func(cmd *cobra.Command, args []string) {

			if options.File != "" {
				options.URLs = utils.ReadFileLines(options.File)
			} else {
				fmt.Println("Reading URLs from standard input. Enter URLs, one per line")
				options.URLs = utils.ReadURLsFromStdin()
			}
			if len(options.URLs) == 0 {
				logger.FATAL("No URLs provided to scan into the file.")
				os.Exit(1)
			}
			runScan(options)
		},
	}

	multiCmd.Flags().StringVarP(&options.File, "list", "l", "", "Specifies a file path containing URLs to scan, with one URL per line. If omitted, URLs will be read from standard input.")
	multiCmd.Flags().StringVarP(&options.OutputFile, "output", "o", "", "Specifies the output file path where results should be saved.")

	return multiCmd
}
