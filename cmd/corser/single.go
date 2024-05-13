package main

import (
	"os"

	"github.com/spf13/cobra"
	"github.com/zomasec/corser/pkg/config"
)

func createSingleCmd(options *config.Options) *cobra.Command {
	var singleCmd = &cobra.Command{
		Use:   "single",
		Short: "Performs a scan on a single specified URL",
		Run: func(cmd *cobra.Command, args []string) {
			// This check is redundant if you're already ensuring via flags that a URL is always provided
			if options.URL == "" {
				logger.FATAL("Single scan requires a URL.")
				os.Exit(1)
			}
			runScan(options)
		},
	}

	// Directly bind the URL flag to the options.URL
	singleCmd.Flags().StringVarP(&options.URL, "url", "u", "", "Specifies the URL to scan for CORS misconfigurations.")
	singleCmd.MarkFlagRequired("url") // This ensures that the command does not run without the URL flag being set

	singleCmd.Flags().StringVarP(&options.PocFile, "generate-poc", "g", "", "Generate a PoC for any vulnerable request with the name of the URL and result found.")

	return singleCmd
}
