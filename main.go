package main



// func main() {

// 	cLevel := flag.Int("c", 30, "Concurrency level or the number of workers to use.")
// 	checkWildcard := flag.Bool("wc", false, "Enable to check the wildcard in Access-Control-Allow-Origin.")
// 	header := flag.String("H", "", "Custom header added to each request.")
// 	method := flag.String("m", "GET", "Specific method name requested with it in each request.")
// 	cookies := flag.String("cookies", "", "Add cookies to each request to access authenticated pages.")
// 	list := flag.String("l", "", "List of URLs to scan.")
// 	timeout := flag.Int("timeout", 5, "Timeout for each request")

// 	flag.Parse()
// 	var Scan *Scanner

// 	if *list != "" {
// 		if err := Scan.ReadURLsFromFile(*list); err != nil {
// 			log.Fatalf("[!] Error reading from a file %s , %v\n", *list, err)
// 		}

// 	} else {
// 		if err := Scan.ReadFromStdin(); err != nil {
// 			log.Fatalf("[!] Error reading from Stdin")
// 		}
// 	}

// 	scan := NewScanner(Scan.URLs, *cLevel, *checkWildcard, NewRequester(*method, *header, *cookies, *timeout))

// 	scan.RunScan()

// }
