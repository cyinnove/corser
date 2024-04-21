package main

import (
	"os"
	"fmt"
	"github.com/spf13/cobra"
	"github.com/zomasec/corser/utils"
)

func createMultiCmd(opts *options) *cobra.Command {
	var multiCmd = &cobra.Command{
		Use:   "multi",
		Short: "Performs scans on multiple URLs from a specified file",
		Run: func(cmd *cobra.Command, args []string) {
			if opts.file == "" {
				fmt.Fprintln(os.Stderr, "Multi scan requires a file with URLs.")
				os.Exit(1)
			}
			urls := utils.ReadFileLines(opts.file)
			runScan(urls, opts)
		},
	}

	multiCmd.Flags().StringVarP(&opts.file, "list", "l", "", "Specifies a file path containing URLs to scan, with one URL per line.")
	multiCmd.Flags().StringVarP(&opts.outputFile, "output", "o", "", "Specifies the output file path where results should be saved.")
	multiCmd.MarkFlagRequired("list")

	return multiCmd
}
