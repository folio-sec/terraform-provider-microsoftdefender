package indicator

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/hashicorp/go-retryablehttp"
)

const (
	maxErrorBodyBytes     = 64 * 1024
	maxResponseBodyBytes  = 16 * 1024 * 1024
	defaultMaxRetries     = 3
	defaultRetryWait      = time.Second
	maximumRetryWait      = 30 * time.Second
	defaultRetryBudget    = 2 * time.Minute
	defaultRequestTimeout = time.Minute
)

type Config struct {
	BaseURL        string
	TokenScope     string
	Credential     azcore.TokenCredential
	HTTPClient     *http.Client
	MaxRetries     int
	Backoff        retryablehttp.Backoff
	RetryBudget    time.Duration
	RequestTimeout time.Duration
}

type Client struct {
	baseURL        *url.URL
	tokenScope     string
	credential     azcore.TokenCredential
	httpClient     *retryablehttp.Client
	retryBudget    time.Duration
	requestTimeout time.Duration
}

type Indicator struct {
	ID                      string   `json:"id,omitempty"`
	IndicatorValue          string   `json:"indicatorValue"`
	IndicatorType           string   `json:"indicatorType"`
	Action                  string   `json:"action"`
	Title                   string   `json:"title"`
	Description             string   `json:"description"`
	Application             *string  `json:"application,omitempty"`
	ExternalID              *string  `json:"externalId,omitempty"`
	ExpirationTime          *string  `json:"expirationTime,omitempty"`
	Severity                string   `json:"severity"`
	RecommendedActions      *string  `json:"recommendedActions,omitempty"`
	EducateURL              *string  `json:"educateUrl,omitempty"`
	RBACGroupNames          []string `json:"rbacGroupNames"`
	RBACGroupIDs            []string `json:"rbacGroupIds,omitempty"`
	GenerateAlert           bool     `json:"generateAlert"`
	SourceType              *string  `json:"sourceType,omitempty"`
	CreatedBySource         *string  `json:"createdBySource,omitempty"`
	CreatedBy               *string  `json:"createdBy,omitempty"`
	LastUpdatedBy           *string  `json:"lastUpdatedBy,omitempty"`
	CreationTimeDateTimeUTC *string  `json:"creationTimeDateTimeUtc,omitempty"`
	LastUpdateTime          *string  `json:"lastUpdateTime,omitempty"`
}

type collection struct {
	Value []Indicator `json:"value"`
}

type HTTPError struct {
	StatusCode int
	Body       []byte
}

// RequestNotSentError identifies failures that occurred before an HTTP
// request could be sent. Mutation outcomes wrapped by this type are known not
// to have changed remote state.
type RequestNotSentError struct{ Err error }

func (e *RequestNotSentError) Error() string { return e.Err.Error() }
func (e *RequestNotSentError) Unwrap() error { return e.Err }

func (e *HTTPError) Error() string {
	return fmt.Sprintf("Defender for Endpoint API returned HTTP %d: %s", e.StatusCode, strings.TrimSpace(string(e.Body)))
}

func New(config Config) (*Client, error) {
	if config.Credential == nil {
		return nil, fmt.Errorf("token credential is required")
	}
	parsed, err := url.Parse(config.BaseURL)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return nil, fmt.Errorf("invalid base URL %q", config.BaseURL)
	}
	if config.TokenScope == "" {
		return nil, fmt.Errorf("token scope is required")
	}
	retryBudget := config.RetryBudget
	if retryBudget == 0 {
		retryBudget = defaultRetryBudget
	}
	if retryBudget < 0 {
		return nil, fmt.Errorf("retry budget must not be negative")
	}
	requestTimeout := config.RequestTimeout
	if requestTimeout == 0 {
		requestTimeout = defaultRequestTimeout
	}
	if requestTimeout < 0 {
		return nil, fmt.Errorf("request timeout must not be negative")
	}
	httpClient := config.HTTPClient
	if httpClient == nil {
		httpClient = http.DefaultClient
	}
	maxRetries := config.MaxRetries
	if maxRetries == 0 {
		maxRetries = defaultMaxRetries
	}
	if maxRetries < 0 {
		return nil, fmt.Errorf("maximum retries must not be negative")
	}
	retryClient := retryablehttp.NewClient()
	retryClient.HTTPClient = httpClient
	retryClient.Logger = nil
	retryClient.RetryMax = maxRetries
	retryClient.RetryWaitMin = defaultRetryWait
	retryClient.RetryWaitMax = maximumRetryWait
	retryClient.CheckRetry = safeGETRetryPolicy
	retryClient.Backoff = defenderBackoff
	retryClient.ErrorHandler = retryablehttp.PassthroughErrorHandler
	if config.Backoff != nil {
		retryClient.Backoff = config.Backoff
	}
	return &Client{
		baseURL:        parsed,
		tokenScope:     config.TokenScope,
		credential:     config.Credential,
		httpClient:     retryClient,
		retryBudget:    retryBudget,
		requestTimeout: requestTimeout,
	}, nil
}

func (c *Client) Submit(ctx context.Context, indicator Indicator) (Indicator, error) {
	var response Indicator
	if err := c.doJSON(ctx, http.MethodPost, "/api/indicators", nil, indicator, &response); err != nil {
		return Indicator{}, err
	}
	return response, nil
}

func (c *Client) FindByValue(ctx context.Context, indicatorValue string) ([]Indicator, error) {
	query := url.Values{}
	query.Set("$filter", "indicatorValue eq '"+escapeODataString(indicatorValue)+"'")
	var response collection
	if err := c.doJSON(ctx, http.MethodGet, "/api/indicators", query, nil, &response); err != nil {
		return nil, err
	}
	return response.Value, nil
}

func (c *Client) Delete(ctx context.Context, id string) error {
	err := c.doJSON(ctx, http.MethodDelete, "/api/indicators/"+url.PathEscape(id), nil, nil, nil)
	var httpErr *HTTPError
	if errors.As(err, &httpErr) && httpErr.StatusCode == http.StatusNotFound {
		return nil
	}
	return err
}

// escapeODataString encodes an OData string literal. The Go standard library
// has no OData literal encoder, and the Defender API has no supported Go SDK;
// OData escapes an apostrophe by doubling it. url.Values performs the separate
// URL query encoding step.
func escapeODataString(value string) string { return strings.ReplaceAll(value, "'", "''") }

func (c *Client) doJSON(ctx context.Context, method, path string, query url.Values, requestBody, responseBody any) error {
	var encoded []byte
	var err error
	if requestBody != nil {
		encoded, err = json.Marshal(requestBody)
		if err != nil {
			return &RequestNotSentError{Err: fmt.Errorf("encode request: %w", err)}
		}
	}
	response, requestErr := c.send(ctx, method, path, query, encoded)
	if requestErr != nil {
		return requestErr
	}
	limit := int64(maxResponseBodyBytes)
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		limit = maxErrorBodyBytes
	}
	body, readErr := io.ReadAll(io.LimitReader(response.Body, limit+1))
	closeErr := response.Body.Close()
	if readErr != nil {
		return fmt.Errorf("read response: %w", readErr)
	}
	bodyExceededLimit := int64(len(body)) > limit
	if bodyExceededLimit && response.StatusCode >= 200 && response.StatusCode < 300 {
		return fmt.Errorf("response body exceeds %d-byte limit", limit)
	}
	if bodyExceededLimit {
		body = body[:limit]
	}
	if closeErr != nil {
		return fmt.Errorf("close response: %w", closeErr)
	}
	if response.StatusCode >= 200 && response.StatusCode < 300 {
		if responseBody != nil && len(body) > 0 {
			if err := json.Unmarshal(body, responseBody); err != nil {
				return fmt.Errorf("decode response: %w", err)
			}
		}
		return nil
	}
	return &HTTPError{StatusCode: response.StatusCode, Body: body}
}

func (c *Client) send(ctx context.Context, method, path string, query url.Values, body []byte) (*http.Response, error) {
	requestCtx := ctx
	timeout := c.requestTimeout
	if method == http.MethodGet {
		timeout = c.retryBudget
	}
	if timeout > 0 {
		var cancel context.CancelFunc
		requestCtx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
	}
	token, err := c.credential.GetToken(requestCtx, policy.TokenRequestOptions{Scopes: []string{c.tokenScope}})
	if err != nil {
		return nil, &RequestNotSentError{Err: fmt.Errorf("acquire Defender for Endpoint access token: %w", err)}
	}
	reference, err := url.Parse(path)
	if err != nil {
		return nil, &RequestNotSentError{Err: fmt.Errorf("parse request path: %w", err)}
	}
	u := c.baseURL.ResolveReference(reference)
	u.RawQuery = query.Encode()
	request, err := retryablehttp.NewRequestWithContext(requestCtx, method, u.String(), body)
	if err != nil {
		return nil, &RequestNotSentError{Err: fmt.Errorf("create HTTP request: %w", err)}
	}
	request.Header.Set("Authorization", "Bearer "+token.Token)
	request.Header.Set("Accept", "application/json")
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	response, err := c.httpClient.Do(request)
	if err != nil {
		return nil, fmt.Errorf("send HTTP request: %w", err)
	}
	return response, nil
}

func retryableStatus(status int) bool {
	switch status {
	case http.StatusTooManyRequests,
		http.StatusInternalServerError,
		http.StatusBadGateway,
		http.StatusServiceUnavailable,
		http.StatusGatewayTimeout:
		return true
	default:
		return false
	}
}

func safeGETRetryPolicy(ctx context.Context, response *http.Response, requestErr error) (bool, error) {
	if ctx.Err() != nil {
		return false, fmt.Errorf("request context ended: %w", ctx.Err())
	}
	if requestErr != nil || response == nil || response.Request == nil || response.Request.Method != http.MethodGet {
		return false, nil
	}
	return retryableStatus(response.StatusCode), nil
}

func defenderBackoff(minimum, maximum time.Duration, attempt int, response *http.Response) time.Duration {
	return min(retryablehttp.DefaultBackoff(minimum, maximum, attempt, response), maximum)
}
