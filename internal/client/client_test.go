package client

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
)

type testRoundTripper func(*http.Request) (*http.Response, error)

func (f testRoundTripper) RoundTrip(request *http.Request) (*http.Response, error) { return f(request) }

func TestAuthenticationMethods(t *testing.T) {
	t.Parallel()
	base := Config{TenantID: "00000000-0000-0000-0000-000000000000", ClientID: "00000000-0000-0000-0000-000000000001"}
	for name, configure := range map[string]func(*Config){
		"client secret":   func(config *Config) { config.ClientSecret = "not-a-real-secret" },
		"OIDC assertion":  func(config *Config) { config.OIDCToken = "not-a-real-assertion" },
		"OIDC token file": func(config *Config) { config.OIDCTokenFilePath = "/not/read/until-token-request" },
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			config := base
			configure(&config)
			configured, err := New(config)
			if err != nil || configured.Indicator == nil {
				t.Fatalf("New() = %#v, %v", configured, err)
			}
		})
	}
}

func TestAuthenticationMethodsAreExclusive(t *testing.T) {
	t.Parallel()
	_, err := New(Config{TenantID: "tenant", ClientID: "client", ClientSecret: "secret", OIDCToken: "super-sensitive-value"})
	if err == nil || !strings.Contains(err.Error(), "mutually exclusive") || strings.Contains(err.Error(), "super-sensitive-value") {
		t.Fatalf("error = %v", err)
	}
}

func TestDefenderEndpointAndScopeAreDistinct(t *testing.T) {
	t.Parallel()
	if DefaultEndpoint != "https://api.security.microsoft.com" || DefaultTokenScope != "https://api.securitycenter.microsoft.com/.default" || strings.Contains(DefaultTokenScope, "graph.microsoft.com") {
		t.Fatalf("endpoint = %q scope = %q", DefaultEndpoint, DefaultTokenScope)
	}
}

func TestAuthenticationUsesAzureDefaultTransportWhenHTTPClientIsNil(t *testing.T) {
	t.Parallel()
	if options := clientOptions(nil); options.Transport != nil {
		t.Fatalf("nil HTTP client produced a non-nil transport: %#v", options.Transport)
	}
	httpClient := &http.Client{}
	if options := clientOptions(httpClient); options.Transport != httpClient {
		t.Fatalf("injected HTTP client was not preserved: %#v", options.Transport)
	}
}

func TestFetchGitHubActionsOIDCAssertion(t *testing.T) {
	t.Parallel()
	httpClient := &http.Client{Transport: testRoundTripper(func(request *http.Request) (*http.Response, error) {
		if request.URL.Query().Get("audience") != DefaultOIDCAudience {
			t.Errorf("audience = %q", request.URL.Query().Get("audience"))
		}
		if request.Header.Get("Authorization") != "Bearer request-credential" {
			t.Errorf("Authorization = %q", request.Header.Get("Authorization"))
		}
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(`{"value":"federated-assertion"}`)), Header: make(http.Header)}, nil
	})}
	assertion, err := fetchGitHubActionsOIDCAssertion(context.Background(), httpClient, "https://oidc.example.test/token?existing=value", "request-credential")
	if err != nil || assertion != "federated-assertion" {
		t.Fatalf("assertion = %q, error = %v", assertion, err)
	}
}

func TestOIDCAssertionErrorsDoNotExposeRequestCredential(t *testing.T) {
	t.Parallel()
	httpClient := &http.Client{Transport: testRoundTripper(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusForbidden, Body: io.NopCloser(strings.NewReader("request-credential")), Header: make(http.Header)}, nil
	})}
	_, err := fetchGitHubActionsOIDCAssertion(context.Background(), httpClient, "https://oidc.example.test/token", "request-credential")
	if err == nil || strings.Contains(err.Error(), "request-credential") {
		t.Fatalf("error = %v", err)
	}
}

func TestGitHubActionsOIDCRequestURLValidation(t *testing.T) {
	t.Parallel()
	for _, requestURL := range []string{
		"http://oidc.example.test/token",
		"https://user@oidc.example.test/token",
		"/relative/token",
		":invalid",
	} {
		_, err := fetchGitHubActionsOIDCAssertion(context.Background(), &http.Client{}, requestURL, "request-credential")
		if err == nil || strings.Contains(err.Error(), "request-credential") {
			t.Errorf("URL %q error = %v", requestURL, err)
		}
	}
}
