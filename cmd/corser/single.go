package main

// import (
//     "fmt"
//     "os"
//     "github.com/zomasec/corser/runner" 
//     "github.com/zomasec/corser/utils"
//     "github.com/spf13/cobra"
// )

// func singleCmd() *cobra.Command {
//     options := &Options{}
// 	var cmd = &cobra.Command{
//         Use:   "single",
//         Short: "Scan a single URL for CORS misconfigurations",
//         Run: func(cmd *cobra.Command, args []string) {
// 			cmd.Flags().String( "file", "", "Specifies a file path containing URLs to scan, with one URL per line.")
// 			// Command-specific flags
//             // flag parsing logic...
//             fmt.Println("Single command")
//         },
//     }
   
//     return cmd
// }

// func multiCmd() *cobra.Command {
//     var cmd = &cobra.Command{
//         Use:   "multi",
//         Short: "Scan multiple URLs from a file for CORS misconfigurations",
//         Run: func(cmd *cobra.Command, args []string) {
//             // Command-specific flags
//             // flag parsing logic...
//             fmt.Println("Multi command")
//         },
//     }
//     // Add flags to the multi command...
//     return cmd
// }
