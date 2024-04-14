package main

// import (
// 	"fmt"
// 	"github.com/zomasec/corser/pkg/pocgen"
// )

// func main() {
// 	config := &pocgen.Config{
// 		Method:    "GET",
// 		TargetURL: "https://example.com/vulnerable-endpoint",
// 	    Params: "param1=value1&param2=value2", // Uncomment for POST
// 		SetRequestHeader: "X-Custom-Header: value", // Optional
// 		CustomOrigin: "zomasec.io@evil.com",
// 	}

// 	err := pocgen.SavePoCToFile(config, "exploit.html")
// 	if err != nil {
// 		fmt.Println("Error generating PoC:", err)
// 		return
// 	}

// 	fmt.Println("PoC saved to exploit.html")
// }
