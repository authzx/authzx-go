package authzx

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

const defaultBaseURL = "https://api.authzx.com/v1"

// Client is the AuthzX SDK client.
type Client struct {
	apiKey     string
	baseURL    string
	httpClient *http.Client
	maxRetries int
}

// ClientOption configures the client.
type ClientOption func(*Client)

// WithBaseURL sets a custom base URL (e.g., "http://localhost:8181" for local agent).
func WithBaseURL(url string) ClientOption {
	return func(c *Client) { c.baseURL = url }
}

// WithHTTPClient sets a custom HTTP client.
func WithHTTPClient(hc *http.Client) ClientOption {
	return func(c *Client) { c.httpClient = hc }
}

// WithTimeout sets the HTTP client timeout.
func WithTimeout(d time.Duration) ClientOption {
	return func(c *Client) { c.httpClient.Timeout = d }
}

// WithRetries sets the max number of retries on transient (5xx) errors. Default is 2.
func WithRetries(n int) ClientOption {
	return func(c *Client) { c.maxRetries = n }
}

// NewClient creates a new AuthzX client.
// For cloud: authzx.NewClient("azx_...")
// For local agent: authzx.NewClient("", authzx.WithBaseURL("http://localhost:8181"))
func NewClient(apiKey string, opts ...ClientOption) *Client {
	c := &Client{
		apiKey:     apiKey,
		baseURL:    defaultBaseURL,
		httpClient: &http.Client{Timeout: 10 * time.Second},
		maxRetries: 2,
	}
	for _, opt := range opts {
		opt(c)
	}
	return c
}

// Check is a convenience method that returns just the boolean result.
func (c *Client) Check(ctx context.Context, subject Subject, action string, resource Resource) (bool, error) {
	resp, err := c.Authorize(ctx, &AuthorizeRequest{
		Subject:  subject,
		Resource: resource,
		Action:   action,
	})
	if err != nil {
		return false, err
	}
	return resp.Allowed, nil
}

func (c *Client) url() string {
	if len(c.baseURL) >= 3 && c.baseURL[len(c.baseURL)-3:] == "/v1" {
		return c.baseURL + "/authorize"
	}
	return c.baseURL + "/v1/authorize"
}

// Authorize sends a full authorization request and returns the detailed response.
func (c *Client) Authorize(ctx context.Context, req *AuthorizeRequest) (*AuthorizeResponse, error) {
	body, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("authzx: failed to marshal request: %w", err)
	}

	var lastErr error
	for attempt := 0; attempt <= c.maxRetries; attempt++ {
		if attempt > 0 {
			time.Sleep(time.Duration(attempt*100) * time.Millisecond)
		}

		httpReq, err := http.NewRequestWithContext(ctx, "POST", c.url(), bytes.NewReader(body))
		if err != nil {
			return nil, fmt.Errorf("authzx: failed to create request: %w", err)
		}
		httpReq.Header.Set("Content-Type", "application/json")
		if c.apiKey != "" {
			httpReq.Header.Set("Authorization", "Bearer "+c.apiKey)
		}

		resp, err := c.httpClient.Do(httpReq)
		if err != nil {
			lastErr = fmt.Errorf("authzx: request failed: %w", err)
			continue
		}

		respBody, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			lastErr = fmt.Errorf("authzx: failed to read response: %w", err)
			continue
		}

		if resp.StatusCode == http.StatusOK {
			var result AuthorizeResponse
			if err := json.Unmarshal(respBody, &result); err != nil {
				return nil, fmt.Errorf("authzx: failed to parse response: %w", err)
			}
			return &result, nil
		}

		apiErr := &Error{StatusCode: resp.StatusCode, Message: string(respBody)}

		// Only retry on 5xx or 429
		if resp.StatusCode >= 500 || resp.StatusCode == 429 {
			lastErr = apiErr
			continue
		}

		return nil, apiErr
	}

	return nil, lastErr
}
