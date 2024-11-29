package digest

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func mockDigestHandler(username, password string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Check if the Authorization header is set
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			// Send a 401 Unauthorized response with a Digest challenge
			w.Header().Set("WWW-Authenticate", `Digest realm="testrealm", nonce="abc123", opaque="xyz789", qop="auth"`)
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		// Validate the Authorization header
		if strings.Contains(authHeader, username) && strings.Contains(authHeader, "response=") {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("Authenticated"))
		} else {
			http.Error(w, "Forbidden", http.StatusForbidden)
		}
	}
}

func TestDigestClient_Get(t *testing.T) {
	// Create a mock server
	username := "testuser"
	password := "testpass"
	server := httptest.NewServer(mockDigestHandler(username, password))
	defer server.Close()

	// Initialize DigestClient
	client := NewDigestClient(username, password, &http.Client{})

	// Create a GET request
	req, err := http.NewRequest("GET", server.URL, nil)
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}

	// Perform the request
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("Error during GET request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status 200 OK, got %d", resp.StatusCode)
	}
}

func TestDigestClient_Post(t *testing.T) {
	// Create a mock server
	username := "testuser"
	password := "testpass"
	server := httptest.NewServer(mockDigestHandler(username, password))
	defer server.Close()

	// Initialize DigestClient
	client := NewDigestClient(username, password, &http.Client{})

	// Create a POST request
	body := strings.NewReader(`{"key": "value"}`)
	req, err := http.NewRequest("POST", server.URL, body)
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")

	// Perform the request
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("Error during POST request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status 200 OK, got %d", resp.StatusCode)
	}
}

func TestDigestClient_Handles401WithoutDigest(t *testing.T) {
	// Create a server that doesn't return a Digest challenge
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
	}))
	defer server.Close()

	// Initialize DigestClient
	client := NewDigestClient("username", "password", &http.Client{})

	// Create a GET request
	req, err := http.NewRequest("GET", server.URL, nil)
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}

	// Perform the request
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("Error during GET request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("Expected status 401 Unauthorized, got %d", resp.StatusCode)
	}
}

func TestDigestClient_DoNoAuth(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "No auth required")
	}))
	defer server.Close()

	client := NewDigestClient("user", "pass", &http.Client{})
	req, err := http.NewRequest("GET", server.URL, nil)
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}

	resp, err := client.DoNoAuth(req)
	if err != nil {
		t.Fatalf("Error during request: %v", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	expected := "No auth required\n"
	if string(body) != expected {
		t.Errorf("Expected response body %q, got %q", expected, string(body))
	}
}
