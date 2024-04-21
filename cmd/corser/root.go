package main

import (
	"fmt"
	"os"
	"github.com/spf13/cobra"
)

type options struct {
	url         string
	method      string
	timeout     int
	concurrency int
	cookie      string
	file        string
	outputFile  string
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
		Short: "Corser is a CLI Application for Advanced CORS Misconfiguration Detection",
		PersistentPreRun: func(cmd *cobra.Command, args []string) {
			banner()
		},
	}

	rootCmd.PersistentFlags().StringVarP(&opts.method, "method", "m", "GET", "Specifies the HTTP method to use when sending requests.")
	rootCmd.PersistentFlags().IntVarP(&opts.timeout, "timeout", "t", 5, "Sets the timeout (in seconds) for each request.")
	rootCmd.PersistentFlags().IntVarP(&opts.concurrency, "concurrency", "c", 10, "Determines the concurrency level.")
	rootCmd.PersistentFlags().StringVarP(&opts.cookie, "cookie", "k", "", "Defines cookies to include in the scan requests.")
	rootCmd.PersistentFlags().StringVarP(&opts.origin, "origin", "O", "http://zomasec.io", "Sets the Origin header value to use in the scan requests.")
	rootCmd.PersistentFlags().StringVarP(&opts.header, "header", "H", "", "Specifies additional headers to include in the scan requests.")
	rootCmd.PersistentFlags().BoolVarP(&opts.deepScan, "deep-scan", "d", false, "Enable deep scan for more advanced CORS bypass techniques.")
	rootCmd.PersistentFlags().BoolVarP(&opts.verbose, "verbose", "v", false, "Enable verbose mode for detailed logs.")

	addCommands(rootCmd, opts)
	rootCmd.Execute()
}

func addCommands(rootCmd *cobra.Command, opts *options) {
	rootCmd.AddCommand(createMultiCmd(opts))
	rootCmd.AddCommand(createSingleCmd(opts))
	
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
