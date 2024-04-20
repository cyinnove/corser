package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"github.com/zomasec/corser/runner"
	"github.com/zomasec/corser/utils"
)

type options struct {
	url         string
	method      string
	timeout     int
	concurrency int
	cookie      string
	file        string
	outputFile  string // New field for output file
	deepScan    bool
	origin      string
	header      string
	verbose     bool
	pocFile     string
}

func main() {
	opts := &options{}

	var rootCmd = &cobra.Command{
		Use:   "corser",
		Short: "Corser Is a CLI Application For Advanced CORS Misconfiguration Detection",
		PersistentPreRun: func(cmd *cobra.Command, args []string) {
			banner()
		},
	}

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
	rootCmd.AddCommand(singleCmd)

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

	// Add the outputFile flag specifically for multi scans
	multiCmd.Flags().StringVarP(&opts.file, "list", "l", "", "Specifies a file path containing URLs to scan, with one URL per line.")
	multiCmd.Flags().StringVarP(&opts.outputFile, "output", "o", "", "Specifies the output file path where results should be saved.")
	multiCmd.MarkFlagRequired("list")
	rootCmd.AddCommand(multiCmd)

	rootCmd.PersistentFlags().StringVarP(&opts.method, "method", "m", "GET", "Specifies the HTTP method to use when sending requests.")
	rootCmd.PersistentFlags().IntVarP(&opts.timeout, "timeout", "t", 5, "Sets the timeout (in seconds) for each request.")
	rootCmd.PersistentFlags().IntVarP(&opts.concurrency, "concurrency", "c", 10, "Determines the concurrency level.")
	rootCmd.PersistentFlags().StringVarP(&opts.cookie, "cookie", "k", "", "Defines cookies to include in the scan requests.")
	rootCmd.PersistentFlags().StringVarP(&opts.origin, "origin", "O", "http://zomasec.io", "Sets the Origin header value to use in the scan requests.")
	rootCmd.PersistentFlags().StringVarP(&opts.header, "header", "H", "", "Specifies additional headers to include in the scan requests.")
	rootCmd.PersistentFlags().BoolVarP(&opts.deepScan, "deep-scan", "d", false, "Enable deep scan for more advanced CORS bypass techniques.")
	rootCmd.PersistentFlags().BoolVarP(&opts.verbose, "verbose", "v", false, "Enable verbose mode for detailed logs.")

	rootCmd.Execute()
}

func runScan(urls []string, opts *options) {
	if len(urls) == 0 {
		fmt.Fprintln(os.Stderr, "No URLs provided to scan.")
		return
	}
	r := runner.NewRunner(urls, opts.method, opts.header, opts.origin, opts.cookie, opts.deepScan, opts.verbose, opts.timeout, opts.concurrency, opts.pocFile, opts.outputFile)
	err := r.Start()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error running scan: %s\n", err)
		os.Exit(1)
	}
}

func banner() {
	logo := `
     ____ ___  ____  ____  _____ ____  
    / ___/ _ \|  _ \/ ___|| ____|  _ \ 
   | |  | | | | |_) \___ \|  _| | |_) |
   | |__| |_| |  _ < ___) | |___|  _ < 
    \____\___/|_| \_\____/|_____|_| \_\   v1.0.0 #Free_Palestine 
    
    coded by: @zomasec contributor: @h0tak88r                                                                                                                            
`
	fmt.Fprintf(os.Stderr, logo)
}
