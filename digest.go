// Package digest provides utilities for making HTTP requests using Digest Authentication.
package digest

import (
	"bytes"
	"crypto/md5"
	"crypto/sha256"
	"encoding/hex"
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
			return c.client.Do(req)
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

// createAuthHeader generates the Authorization header for Digest Authentication,
// supporting multiple algorithms.
func (c *DigestClient) createAuthHeader(req *http.Request, auth authDetails) string {
	nc := "00000001"
	cnonce := generateCNonce()

	// Compute HA1 and HA2
	ha1 := computeHA1(c.username, c.password, auth, cnonce)
	ha2 := computeHA2(req.Method, req.URL.String(), auth)

	// Compute response hash
	response := computeResponseHash(ha1, ha2, auth, nc, cnonce)

	// Build Authorization header
	return fmt.Sprintf(
		`Digest username="%s", realm="%s", nonce="%s", uri="%s", response="%s", qop=%s, nc=%s, cnonce="%s", algorithm="%s"`,
		c.username,
		auth.realm,
		auth.nonce,
		req.URL.String(),
		response,
		auth.qop,
		nc,
		cnonce,
		auth.algorithm,
	)
}

// computeHA1 calculates HA1 based on the authentication algorithm.
func computeHA1(username, password string, auth authDetails, cnonce string) string {
	switch strings.ToLower(auth.algorithm) {
	case "md5", "":
		return md5Hash(fmt.Sprintf("%s:%s:%s", username, auth.realm, password))
	case "md5-sess":
		initialHA1 := md5Hash(fmt.Sprintf("%s:%s:%s", username, auth.realm, password))
		return md5Hash(fmt.Sprintf("%s:%s:%s", initialHA1, auth.nonce, cnonce))
	case "sha-256":
		return sha256Hash(fmt.Sprintf("%s:%s:%s", username, auth.realm, password))
	case "sha-256-sess":
		initialHA1 := sha256Hash(fmt.Sprintf("%s:%s:%s", username, auth.realm, password))
		return sha256Hash(fmt.Sprintf("%s:%s:%s", initialHA1, auth.nonce, cnonce))
	default:
		panic(fmt.Sprintf("unsupported digest algorithm: %s", auth.algorithm))
	}
}

// computeHA2 calculates HA2 based on the request method and URI.
func computeHA2(method, uri string, auth authDetails) string {
	switch strings.ToLower(auth.algorithm) {
	case "sha-256", "sha-256-sess":
		return sha256Hash(fmt.Sprintf("%s:%s", method, uri))
	default: // Default to MD5
		return md5Hash(fmt.Sprintf("%s:%s", method, uri))
	}
}

// computeResponseHash calculates the response hash for the digest authentication header.
func computeResponseHash(ha1, ha2 string, auth authDetails, nc, cnonce string) string {
	data := fmt.Sprintf("%s:%s:%s:%s:%s:%s", ha1, auth.nonce, nc, cnonce, auth.qop, ha2)
	switch strings.ToLower(auth.algorithm) {
	case "sha-256", "sha-256-sess":
		return sha256Hash(data)
	default:
		return md5Hash(data)
	}
}

// md5Hash calculates the MD5 hash of a string.
func md5Hash(data string) string {
	hash := md5.New()
	_, _ = io.WriteString(hash, data)
	return hex.EncodeToString(hash.Sum(nil))
}

// sha256Hash calculates the SHA-256 hash of a string.
func sha256Hash(data string) string {
	hash := sha256.New()
	_, _ = io.WriteString(hash, data)
	return hex.EncodeToString(hash.Sum(nil))
}

// generateCNonce generates a client nonce for the request.
func generateCNonce() string {
	return md5Hash(fmt.Sprintf("%d", time.Now().UnixNano()))
}
