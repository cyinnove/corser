package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"github.com/zomasec/corser/pkg/config"
)

func main() {
	options := &config.Options{
		URLs: []string{},
	}
	proxyOptions := &config.ProxyOptions{}

	var rootCmd = &cobra.Command{
		Use:   "corser",
		Short: "Corser is a CLI Application for Advanced CORS Misconfiguration Detection",
		PersistentPreRun: func(cmd *cobra.Command, args []string) {
			banner()
		},
	}

	rootCmd.PersistentFlags().StringVarP(&options.Method, "method", "m", "GET", "Specifies the HTTP method to use when sending requests.")
	rootCmd.PersistentFlags().IntVarP(&options.Timeout, "timeout", "t", 5, "Sets the timeout (in seconds) for each request.")
	rootCmd.PersistentFlags().IntVarP(&options.Concurrency, "concurrency", "c", 10, "Determines the concurrency level.")
	rootCmd.PersistentFlags().StringVarP(&options.Cookies, "cookie", "k", "", "Defines cookies to include in the scan requests.")
	rootCmd.PersistentFlags().StringVarP(&options.Origin, "origin", "O", "https://zomasec.io", "Sets the Origin header value to use in the scan requests.")
	rootCmd.PersistentFlags().StringVarP(&options.Header, "header", "H", "", "Specifies additional headers to include in the scan requests.")
	rootCmd.PersistentFlags().BoolVarP(&options.IsDeep, "deep-scan", "d", false, "Enable deep scan for more advanced CORS bypass techniques.")
	rootCmd.PersistentFlags().BoolVarP(&options.Verbose, "verbose", "v", false, "Enable verbose mode for detailed logs.")

	rootCmd.AddCommand(createSingleCmd(options))
	rootCmd.AddCommand(createMultiCmd(options))
	rootCmd.AddCommand(createProxyCmd(proxyOptions))

	_ = rootCmd.Execute()
}

func banner() {
	logo := `
     ____ ___  ____  ____  _____ ____  
    / ___/ _ \|  _ \/ ___|| ____|  _ \ 
   | |  | | | | |_) \___ \|  _| | |_) |
   | |__| |_| |  _ < ___) | |___|  _ < 
    \____\___/|_| \_\____/|_____|_| \_\   v1.0 #Free_Palestine 
    
    developed by: @zomasec contributor: @h0tak88r                                                                                                                            

`
	fmt.Fprintf(os.Stderr, logo)
}
