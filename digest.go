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

// authDetails holds the parameters parsed from a WWW-Authenticate header.
type authDetails struct {
	realm     string
	nonce     string
	opaque    string
	qop       string
	algorithm string
}

// DigestClient is used to make HTTP requests with Digest Authentication.
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

// Do performs an HTTP request using Digest Authentication. If the first attempt
// returns a 401 Unauthorized and the response includes a Digest challenge, the request
// is retried with an appropriate Authorization header.
// Note: the original request is modified in-place.
func (c *DigestClient) Do(req *http.Request) (*http.Response, error) {
	var savedBody []byte
	var err error

	// If a body is present and GetBody is not provided, read and buffer it.
	// (If GetBody is provided, it will be used to reset the body on retry.)
	if req.Body != nil && req.GetBody == nil {
		savedBody, err = io.ReadAll(req.Body)
		if err != nil {
			return nil, fmt.Errorf("failed to read request body: %w", err)
		}
		// Reset the body for the first request.
		req.Body = io.NopCloser(bytes.NewReader(savedBody))
	}

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, err
	}

	// If unauthorized, check for a Digest challenge and retry.
	if resp.StatusCode == http.StatusUnauthorized {
		resp.Body.Close()

		authHeader := resp.Header.Get("WWW-Authenticate")
		if strings.HasPrefix(authHeader, "Digest ") {
			auth := parseAuthDetails(authHeader)

			// Reset the body for the retry.
			if req.Body != nil {
				if req.GetBody != nil {
					var err error
					req.Body, err = req.GetBody()
					if err != nil {
						return nil, fmt.Errorf("failed to reset request body: %w", err)
					}
				} else {
					req.Body = io.NopCloser(bytes.NewReader(savedBody))
				}
			}

			authValue, err := c.createAuthHeader(req, auth)
			if err != nil {
				return nil, err
			}
			req.Header.Set("Authorization", authValue)
			return c.client.Do(req)
		}
	}
	return resp, nil
}

// DoNoAuth performs an HTTP request without attempting Digest Authentication.
func (c *DigestClient) DoNoAuth(req *http.Request) (*http.Response, error) {
	return c.client.Do(req)
}

// parseAuthDetails extracts the digest authentication parameters from a challenge header.
func parseAuthDetails(header string) authDetails {
	auth := authDetails{}
	trimmed := strings.TrimPrefix(header, "Digest ")
	fields := strings.Split(trimmed, ",")
	for _, field := range fields {
		field = strings.TrimSpace(field)
		if field == "" {
			continue
		}
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

// createAuthHeader generates the Digest Authorization header for the given request and auth details.
func (c *DigestClient) createAuthHeader(req *http.Request, auth authDetails) (string, error) {
	// Use a fixed nonce count ("nc") value.
	nc := "00000001"
	cnonce := generateCNonce()

	ha1, err := computeHA1(c.username, c.password, auth, cnonce)
	if err != nil {
		return "", err
	}
	// Use RequestURI (path + query) per the spec.
	ha2 := computeHA2(req.Method, req.URL.RequestURI(), auth)
	response := computeResponseHash(ha1, ha2, auth, nc, cnonce)

	header := fmt.Sprintf(
		`Digest username="%s", realm="%s", nonce="%s", uri="%s", response="%s", qop=%s, nc=%s, cnonce="%s", algorithm="%s"`,
		c.username,
		auth.realm,
		auth.nonce,
		req.URL.RequestURI(),
		response,
		auth.qop,
		nc,
		cnonce,
		auth.algorithm,
	)
	if auth.opaque != "" {
		header += fmt.Sprintf(`, opaque="%s"`, auth.opaque)
	}
	return header, nil
}

// computeHA1 calculates HA1 according to the algorithm specified in the challenge.
func computeHA1(username, password string, auth authDetails, cnonce string) (string, error) {
	switch strings.ToLower(auth.algorithm) {
	case "", "md5":
		return md5Hash(fmt.Sprintf("%s:%s:%s", username, auth.realm, password)), nil
	case "md5-sess":
		initial := md5Hash(fmt.Sprintf("%s:%s:%s", username, auth.realm, password))
		return md5Hash(fmt.Sprintf("%s:%s:%s", initial, auth.nonce, cnonce)), nil
	case "sha-256":
		return sha256Hash(fmt.Sprintf("%s:%s:%s", username, auth.realm, password)), nil
	case "sha-256-sess":
		initial := sha256Hash(fmt.Sprintf("%s:%s:%s", username, auth.realm, password))
		return sha256Hash(fmt.Sprintf("%s:%s:%s", initial, auth.nonce, cnonce)), nil
	default:
		return "", fmt.Errorf("unsupported digest algorithm: %s", auth.algorithm)
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

// computeResponseHash calculates the digest response hash.
func computeResponseHash(ha1, ha2 string, auth authDetails, nc, cnonce string) string {
	data := fmt.Sprintf("%s:%s:%s:%s:%s:%s", ha1, auth.nonce, nc, cnonce, auth.qop, ha2)
	switch strings.ToLower(auth.algorithm) {
	case "sha-256", "sha-256-sess":
		return sha256Hash(data)
	default:
		return md5Hash(data)
	}
}

// md5Hash returns the MD5 hash of the given string.
func md5Hash(data string) string {
	hash := md5.New()
	_, _ = io.WriteString(hash, data)
	return hex.EncodeToString(hash.Sum(nil))
}

// sha256Hash returns the SHA-256 hash of the given string.
func sha256Hash(data string) string {
	hash := sha256.New()
	_, _ = io.WriteString(hash, data)
	return hex.EncodeToString(hash.Sum(nil))
}

// generateCNonce generates a client nonce based on the current time.
func generateCNonce() string {
	return md5Hash(fmt.Sprintf("%d", time.Now().UnixNano()))
}
