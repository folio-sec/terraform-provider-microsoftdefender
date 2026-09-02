package indicator

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
)

type fakeCredential struct {
	token azcore.AccessToken
	err   error
	scope string
}

type roundTripFunc func(*http.Request) (*http.Response, error)

type repeatedByteReader struct{}

type contextBoundBody struct {
	context context.Context
	reader  io.Reader
}

func (body *contextBoundBody) Read(buffer []byte) (int, error) {
	if err := body.context.Err(); err != nil {
		return 0, err
	}
	return body.reader.Read(buffer)
}

func (*contextBoundBody) Close() error { return nil }

func (repeatedByteReader) Read(buffer []byte) (int, error) {
	for index := range buffer {
		buffer[index] = 'x'
	}
	return len(buffer), nil
}

func (f roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) { return f(request) }

func (c *fakeCredential) GetToken(_ context.Context, options policy.TokenRequestOptions) (azcore.AccessToken, error) {
	if len(options.Scopes) == 1 {
		c.scope = options.Scopes[0]
	}
	return c.token, c.err
}

func TestAuthorizationPostAndResponseDecode(t *testing.T) {
	t.Parallel()
	var received string
	httpClient := clientWithTransport(func(request *http.Request) *http.Response {
		if got := request.Header.Get("Authorization"); got != "Bearer secret-token" {
			t.Errorf("Authorization = %q", got)
		}
		if got := request.Header.Get("Content-Type"); got != "application/json" {
			t.Errorf("Content-Type = %q", got)
		}
		body, err := io.ReadAll(request.Body)
		if err != nil {
			t.Fatal(err)
		}
		received = string(body)
		return jsonResponse(http.StatusOK, `{"id":"42","indicatorValue":"abcd","indicatorType":"FileSha256","action":"Allowed","title":"title","description":"description","severity":"Informational","rbacGroupNames":[],"generateAlert":false}`)
	})

	credential := &fakeCredential{token: azcore.AccessToken{Token: "secret-token"}}
	client := testClient(t, "https://example.test", credential, httpClient)
	educateURL := "https://support.example.test/indicator"
	result, err := client.Submit(context.Background(), Indicator{IndicatorValue: "abcd", IndicatorType: "FileSha256", Action: "Allowed", Title: "title", Description: "description", Severity: "Informational", EducateURL: &educateURL, RBACGroupNames: []string{}})
	if err != nil {
		t.Fatal(err)
	}
	if result.ID != "42" {
		t.Fatalf("ID = %q", result.ID)
	}
	for _, fragment := range []string{`"indicatorValue":"abcd"`, `"educateUrl":"https://support.example.test/indicator"`, `"rbacGroupNames":[]`, `"generateAlert":false`} {
		if !strings.Contains(received, fragment) {
			t.Errorf("request body %q does not contain %q", received, fragment)
		}
	}
	if strings.Contains(received, `"id"`) {
		t.Errorf("request body unexpectedly contains API ID: %s", received)
	}
	if credential.scope != "scope/.default" {
		t.Errorf("scope = %q", credential.scope)
	}
}

func TestFindByValueEscapesODataAndDecodesCollection(t *testing.T) {
	t.Parallel()
	indicatorValue := "a' or indicatorValue ne 'b"
	httpClient := clientWithTransport(func(request *http.Request) *http.Response {
		if got := request.URL.Query().Get("$filter"); got != "indicatorValue eq 'a'' or indicatorValue ne ''b'" {
			t.Errorf("filter = %q", got)
		}
		return jsonResponse(http.StatusOK, `{"value":[{"id":"7","indicatorValue":"a' or indicatorValue ne 'b","indicatorType":"DomainName","action":"Allowed","title":"title","description":"description","externalId":"correlation-7","sourceType":"AadApp","createdBySource":"example-app","createdBy":"principal-1","lastUpdatedBy":"principal-2","creationTimeDateTimeUtc":"2026-09-01T00:00:00Z","lastUpdateTime":"2026-09-01T01:00:00Z","severity":"Low","rbacGroupNames":["B","A"],"rbacGroupIds":["group-1"],"generateAlert":true}]}`)
	})
	results, err := testClient(t, "https://example.test", validCredential(), httpClient).FindByValue(context.Background(), indicatorValue)
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 1 || results[0].ID != "7" || len(results[0].RBACGroupNames) != 2 ||
		results[0].ExternalID == nil || *results[0].ExternalID != "correlation-7" ||
		len(results[0].RBACGroupIDs) != 1 || results[0].CreationTimeDateTimeUTC == nil {
		t.Fatalf("results = %#v", results)
	}
}

func TestRequestContextRemainsActiveWhileReadingResponse(t *testing.T) {
	t.Parallel()
	httpClient := &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     make(http.Header),
			Body: &contextBoundBody{
				context: request.Context(),
				reader:  strings.NewReader(`{"value":[]}`),
			},
			Request: request,
		}, nil
	})}
	if _, err := testClient(t, "https://example.test", validCredential(), httpClient).FindByValue(context.Background(), "value"); err != nil {
		t.Fatal(err)
	}
}

func TestDelete204And404(t *testing.T) {
	t.Parallel()
	for _, status := range []int{http.StatusNoContent, http.StatusNotFound} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			t.Parallel()
			httpClient := clientWithTransport(func(request *http.Request) *http.Response {
				if request.Method != http.MethodDelete || request.URL.EscapedPath() != "/api/indicators/id%2Fwith%2Fslash" {
					t.Errorf("request = %s %s", request.Method, request.URL.EscapedPath())
				}
				return jsonResponse(status, "")
			})
			if err := testClient(t, "https://example.test", validCredential(), httpClient).Delete(context.Background(), "id/with/slash"); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestTypedErrors(t *testing.T) {
	t.Parallel()
	for _, status := range []int{400, 401, 403, 429, 500} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			t.Parallel()
			requests := 0
			httpClient := clientWithTransport(func(*http.Request) *http.Response {
				requests++
				return jsonResponse(status, `{"error":"details"}`)
			})
			_, err := testClient(t, "https://example.test", validCredential(), httpClient).Submit(context.Background(), Indicator{})
			var httpErr *HTTPError
			if !errors.As(err, &httpErr) || httpErr.StatusCode != status || !strings.Contains(string(httpErr.Body), "details") {
				t.Fatalf("error = %#v", err)
			}
			if requests != 1 {
				t.Fatalf("mutation requests = %d, want 1", requests)
			}
		})
	}
}

func TestSuccessfulResponseBodyIsBounded(t *testing.T) {
	t.Parallel()
	httpClient := clientWithTransport(func(*http.Request) *http.Response {
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     make(http.Header),
			Body:       io.NopCloser(io.LimitReader(repeatedByteReader{}, maxResponseBodyBytes+1)),
		}
	})
	_, err := testClient(t, "https://example.test", validCredential(), httpClient).FindByValue(context.Background(), "value")
	if err == nil || !strings.Contains(err.Error(), "response body exceeds") {
		t.Fatalf("error = %v", err)
	}
}

func TestGetRetryAfter(t *testing.T) {
	t.Parallel()
	requests := 0
	var delay time.Duration
	httpClient := clientWithTransport(func(*http.Request) *http.Response {
		requests++
		if requests == 1 {
			response := jsonResponse(http.StatusTooManyRequests, "")
			response.Header.Set("Retry-After", "7")
			return response
		}
		return jsonResponse(http.StatusOK, `{"value":[]}`)
	})
	client := testClient(t, "https://example.test", validCredential(), httpClient)
	originalBackoff := client.httpClient.Backoff
	client.httpClient.Backoff = func(minimum, maximum time.Duration, attempt int, response *http.Response) time.Duration {
		delay = originalBackoff(minimum, maximum, attempt, response)
		return 0
	}
	if _, err := client.FindByValue(context.Background(), "value"); err != nil {
		t.Fatal(err)
	}
	if requests != 2 {
		t.Fatalf("requests = %d, want 2", requests)
	}
	if delay != 7*time.Second {
		t.Fatalf("Retry-After delay = %s, want 7s", delay)
	}
}

func TestGet429StopsAfterConfiguredRetries(t *testing.T) {
	t.Parallel()
	requests := 0
	httpClient := clientWithTransport(func(*http.Request) *http.Response {
		requests++
		return jsonResponse(http.StatusTooManyRequests, `{"error":"rate limited"}`)
	})
	client := testClient(t, "https://example.test", validCredential(), httpClient)
	client.httpClient.Backoff = func(time.Duration, time.Duration, int, *http.Response) time.Duration { return 0 }
	_, err := client.FindByValue(context.Background(), "value")
	var httpErr *HTTPError
	if !errors.As(err, &httpErr) || httpErr.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("error = %#v", err)
	}
	if requests != 3 {
		t.Fatalf("requests = %d, want initial request plus 2 retries", requests)
	}
}

func TestRetryableStatusIsLimitedToTransientResponses(t *testing.T) {
	t.Parallel()
	for _, status := range []int{429, 500, 502, 503, 504} {
		if !retryableStatus(status) {
			t.Errorf("status %d should be retryable", status)
		}
	}
	for _, status := range []int{400, 401, 403, 501, 505, 599} {
		if retryableStatus(status) {
			t.Errorf("status %d should not be retryable", status)
		}
	}
}

func TestRetryAfterIsCapped(t *testing.T) {
	t.Parallel()
	response := jsonResponse(http.StatusTooManyRequests, "")
	response.Header.Set("Retry-After", "3600")
	if delay := defenderBackoff(time.Second, 30*time.Second, 0, response); delay != 30*time.Second {
		t.Fatalf("delay = %s, want 30s", delay)
	}
}

func TestGETRetryBudgetBoundsRetryAfterWait(t *testing.T) {
	t.Parallel()
	requests := 0
	httpClient := clientWithTransport(func(*http.Request) *http.Response {
		requests++
		response := jsonResponse(http.StatusTooManyRequests, `{"error":"rate limited"}`)
		response.Header.Set("Retry-After", "30")
		return response
	})
	client, err := New(Config{
		BaseURL:     "https://example.test",
		TokenScope:  "scope/.default",
		Credential:  validCredential(),
		HTTPClient:  httpClient,
		MaxRetries:  2,
		RetryBudget: 20 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	started := time.Now()
	_, err = client.FindByValue(context.Background(), "value")
	if err == nil || !strings.Contains(err.Error(), "context deadline exceeded") {
		t.Fatalf("error = %v", err)
	}
	if elapsed := time.Since(started); elapsed > time.Second {
		t.Fatalf("retry budget took %s", elapsed)
	}
	if requests != 1 {
		t.Fatalf("requests = %d, want only the initial request", requests)
	}
}

func TestMutationRequestTimeout(t *testing.T) {
	t.Parallel()
	requests := 0
	httpClient := &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		requests++
		<-request.Context().Done()
		return nil, request.Context().Err()
	})}
	client, err := New(Config{
		BaseURL:        "https://example.test",
		TokenScope:     "scope/.default",
		Credential:     validCredential(),
		HTTPClient:     httpClient,
		MaxRetries:     2,
		RequestTimeout: 20 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = client.Submit(context.Background(), Indicator{})
	if err == nil || !strings.Contains(err.Error(), "context deadline exceeded") {
		t.Fatalf("error = %v", err)
	}
	if requests != 1 {
		t.Fatalf("mutation requests = %d, want 1", requests)
	}
}

func TestTokenError(t *testing.T) {
	t.Parallel()
	client := testClient(t, "https://example.invalid", &fakeCredential{err: errors.New("credential failed")}, &http.Client{})
	_, err := client.FindByValue(context.Background(), "value")
	if err == nil || !strings.Contains(err.Error(), "acquire Defender for Endpoint access token") || strings.Contains(err.Error(), "secret-token") {
		t.Fatalf("error = %v", err)
	}
	var notSent *RequestNotSentError
	if !errors.As(err, &notSent) {
		t.Fatalf("error type = %T, want RequestNotSentError", err)
	}
}

func testClient(t *testing.T, baseURL string, credential azcore.TokenCredential, httpClient *http.Client) *Client {
	t.Helper()
	result, err := New(Config{BaseURL: baseURL, TokenScope: "scope/.default", Credential: credential, HTTPClient: httpClient, MaxRetries: 2})
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func validCredential() azcore.TokenCredential {
	return &fakeCredential{token: azcore.AccessToken{Token: "secret-token", ExpiresOn: time.Now().Add(time.Hour)}}
}

func clientWithTransport(handler func(*http.Request) *http.Response) *http.Client {
	return &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		response := handler(request)
		response.Request = request
		return response, nil
	})}
}

func jsonResponse(status int, body string) *http.Response {
	return &http.Response{StatusCode: status, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(body))}
}
