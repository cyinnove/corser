package main

import (
	"fmt"
	"net/http"
)

func main(){
req, err := http.NewRequest("OPTIONS", "http://127.0.0.1:3000/api/3", nil)
if err != nil {

	return 
}


resp, err := http.DefaultClient.Do(req)
if err != nil {
	return 
}
fmt.Println(resp)
defer resp.Body.Close()

}