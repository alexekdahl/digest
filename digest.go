// Package digest provides utilities for making HTTP requests using Digest Authentication.
package digest

import (
	"bytes"
	"crypto/md5"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// authDetails holds the details of the Digest Authentication challenge.
type authDetails struct {
	realm     string
	nonce     string
	opaque    string
	qop       string
	algorithm string
}

// DigestClient is used to make Digest Authenticated HTTP requests.
type DigestClient struct {
	username string
	password string
	client   *http.Client
}

// NewDigestClient creates a new DigestClient.
func NewDigestClient(username, password string, client *http.Client) *DigestClient {
	return &DigestClient{
		username: username,
		password: password,
		client:   client,
	}
}

// Do performs an HTTP request using Digest Authentication.
// If the request is unauthenticated (401), it retries with the Authorization header.
func (c *DigestClient) Do(req *http.Request) (*http.Response, error) {
	var bodyBytes []byte
	var err error

	// Save the original body if present
	if req.Body != nil {
		bodyBytes, err = io.ReadAll(req.Body)
		if err != nil {
			return nil, fmt.Errorf("failed to read request body: %v", err)
		}
		req.Body = io.NopCloser(bytes.NewReader(bodyBytes)) // Reset body for the first request
	}

	// First attempt
	resp, err := c.client.Do(req)
	if err != nil {
		return nil, err
	}

	// If unauthorized, retry with Digest Authentication
	if resp.StatusCode == http.StatusUnauthorized {
		authHeader := resp.Header.Get("WWW-Authenticate")
		if strings.HasPrefix(authHeader, "Digest ") {
			auth := parseAuthDetails(authHeader)
			// Reset the body for retry
			if bodyBytes != nil {
				req.Body = io.NopCloser(bytes.NewReader(bodyBytes))
			}

			req.Header.Set("Authorization", c.createAuthHeader(req, auth))
			return c.client.Do(req) // Retry
		}
	}
	return resp, nil
}

// DoNoAuth performs an HTTP request without attempting Digest Authentication.
func (c *DigestClient) DoNoAuth(req *http.Request) (*http.Response, error) {
	return c.client.Do(req)
}

// parseAuthDetails extracts the details from a Digest Authentication header.
func parseAuthDetails(header string) authDetails {
	auth := authDetails{}
	fields := strings.Split(header[len("Digest "):], ", ")
	for _, field := range fields {
		parts := strings.SplitN(field, "=", 2)
		if len(parts) != 2 {
			continue
		}
		key := strings.TrimSpace(parts[0])
		value := strings.Trim(parts[1], `"`)
		switch key {
		case "realm":
			auth.realm = value
		case "nonce":
			auth.nonce = value
		case "opaque":
			auth.opaque = value
		case "qop":
			auth.qop = value
		case "algorithm":
			auth.algorithm = value
		}
	}
	return auth
}

// createAuthHeader generates the Authorization header for Digest Authentication.
func (c *DigestClient) createAuthHeader(req *http.Request, auth authDetails) string {
	ha1 := fmt.Sprintf("%x", md5.Sum([]byte(fmt.Sprintf("%s:%s:%s", c.username, auth.realm, c.password))))
	ha2 := fmt.Sprintf("%x", md5.Sum([]byte(fmt.Sprintf("%s:%s", req.Method, req.URL.String()))))
	nc := "00000001"
	cnonce := generateCNonce()

	response := md5Hash(fmt.Sprintf("%s:%s:%s:%s:%s:%s",
		ha1, auth.nonce, nc, cnonce, auth.qop, ha2))

	authHeader := fmt.Sprintf(
		`Digest username="%s", realm="%s", nonce="%s", uri="%s", response="%s", qop=%s, nc=%s, cnonce="%s"`,
		c.username,
		auth.realm,
		auth.nonce,
		req.URL.String(),
		response,
		auth.qop,
		nc,
		cnonce,
	)

	return authHeader
}

// generateCNonce generates a client nonce for the request.
func generateCNonce() string {
	return fmt.Sprintf("%x", md5.Sum([]byte(fmt.Sprintf("%d", time.Now().UnixNano()))))
}

// md5Hash calculates the MD5 hash of a string.
func md5Hash(data string) string {
	hash := md5.New()
	_, _ = io.WriteString(hash, data)
	return fmt.Sprintf("%x", hash.Sum(nil))
}
