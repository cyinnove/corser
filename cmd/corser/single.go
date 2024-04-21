package main

import (
	"fmt"
	"os"
	"github.com/spf13/cobra"
)

func createSingleCmd(opts *options) *cobra.Command {
	var singleCmd = &cobra.Command{
		Use:   "single",
		Short: "Performs a scan on a single specified URL",
		Run: func(cmd *cobra.Command, args []string) {
			if opts.url == "" {
				fmt.Fprintln(os.Stderr, "Single scan requires a URL.")
				os.Exit(1)
			}
			urls := []string{opts.url}
			runScan(urls, opts)
		},
	}

	singleCmd.Flags().StringVarP(&opts.url, "url", "u", "", "Specifies the URL to scan for CORS misconfigurations.")
	singleCmd.Flags().StringVarP(&opts.pocFile, "gen-poc", "g", "", "Generate a PoC for any vulnerable request with the name of the URL and result found.")
	singleCmd.MarkFlagRequired("url")

	return singleCmd
}
