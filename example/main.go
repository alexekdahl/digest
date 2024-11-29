package main

import (
	"bytes"
	"fmt"
	"io"
	"net/http"

	"github.com/alexekdahl/digest"
)

func main() {
	client := digest.NewDigestClient("username", "password", &http.Client{})

	// Example for GET request
	req, err := http.NewRequest("GET", "http://example.com/protected", nil)
	if err != nil {
		fmt.Println("Error creating GET request:", err)
		return
	}

	resp, err := client.Do(req)
	if err != nil {
		fmt.Println("Error performing GET request:", err)
		return
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	fmt.Println("GET Response:", string(body))

	// Example for POST request
	postData := []byte(`{"key": "value"}`)
	req, err = http.NewRequest("POST", "http://example.com/protected", bytes.NewReader(postData))
	if err != nil {
		fmt.Println("Error creating POST request:", err)
		return
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err = client.Do(req)
	if err != nil {
		fmt.Println("Error performing POST request:", err)
		return
	}
	defer resp.Body.Close()

	body, _ = io.ReadAll(resp.Body)
	fmt.Println("POST Response:", string(body))
}
