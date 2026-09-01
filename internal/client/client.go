package client

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	indicatorclient "github.com/folio-sec/terraform-provider-microsoftdefender/internal/client/endpoint/indicator"
)

const (
	DefaultEndpoint     = "https://api.security.microsoft.com"
	DefaultOIDCAudience = "api://AzureADTokenExchange"
	// DefaultTokenScope intentionally differs from DefaultEndpoint. Defender for
	// Endpoint native APIs still expect this legacy token audience.
	DefaultTokenScope = "https://api.securitycenter.microsoft.com/.default" // #nosec G101 -- public OAuth scope, not a credential.
)

type Config struct {
	TenantID               string
	ClientID               string
	ClientSecret           string
	OIDCToken              string
	OIDCTokenFilePath      string
	GitHubOIDCRequestURL   string
	GitHubOIDCRequestToken string
	Endpoint               string
	TokenScope             string
	HTTPClient             *http.Client
	Credential             azcore.TokenCredential
}

type Client struct {
	Indicator *indicatorclient.Client
}

func New(config Config) (*Client, error) {
	if config.TenantID == "" && config.Credential == nil {
		return nil, fmt.Errorf("tenant_id must be configured")
	}
	if config.ClientID == "" && config.Credential == nil {
		return nil, fmt.Errorf("client_id must be configured")
	}
	credential := config.Credential
	if credential == nil {
		configuredMethods := 0
		for _, value := range []string{config.ClientSecret, config.OIDCToken, config.OIDCTokenFilePath} {
			if value != "" {
				configuredMethods++
			}
		}
		if config.GitHubOIDCRequestURL != "" || config.GitHubOIDCRequestToken != "" {
			if config.GitHubOIDCRequestURL == "" || config.GitHubOIDCRequestToken == "" {
				return nil, fmt.Errorf("GitHub OIDC request URL and token must be configured together")
			}
			configuredMethods++
		}
		if configuredMethods == 0 {
			return nil, fmt.Errorf("configure client_secret or an OIDC assertion source")
		}
		if configuredMethods > 1 {
			return nil, fmt.Errorf("client_secret and OIDC assertion sources are mutually exclusive")
		}
		created, err := credentialFromConfig(config)
		if err != nil {
			return nil, err
		}
		credential = created
	}
	endpoint := config.Endpoint
	if endpoint == "" {
		endpoint = DefaultEndpoint
	}
	scope := config.TokenScope
	if scope == "" {
		scope = DefaultTokenScope
	}
	apiClient, err := indicatorclient.New(indicatorclient.Config{
		BaseURL: endpoint, TokenScope: scope, Credential: credential, HTTPClient: config.HTTPClient,
	})
	if err != nil {
		return nil, fmt.Errorf("create Indicator API client: %w", err)
	}
	return &Client{Indicator: apiClient}, nil
}

func credentialFromConfig(config Config) (azcore.TokenCredential, error) {
	identityClientOptions := clientOptions(config.HTTPClient)
	if config.GitHubOIDCRequestURL != "" {
		httpClient := config.HTTPClient
		if httpClient == nil {
			httpClient = http.DefaultClient
		}
		credential, err := azidentity.NewClientAssertionCredential(config.TenantID, config.ClientID, func(ctx context.Context) (string, error) {
			return fetchGitHubActionsOIDCAssertion(ctx, httpClient, config.GitHubOIDCRequestURL, config.GitHubOIDCRequestToken)
		}, &azidentity.ClientAssertionCredentialOptions{ClientOptions: identityClientOptions})
		if err != nil {
			return nil, fmt.Errorf("create requested OIDC client assertion credential: %w", err)
		}
		return credential, nil
	}
	if config.OIDCTokenFilePath != "" {
		credential, err := azidentity.NewWorkloadIdentityCredential(&azidentity.WorkloadIdentityCredentialOptions{
			ClientOptions: identityClientOptions, TenantID: config.TenantID, ClientID: config.ClientID, TokenFilePath: config.OIDCTokenFilePath,
		})
		if err != nil {
			return nil, fmt.Errorf("create workload identity credential: %w", err)
		}
		return credential, nil
	}
	if config.OIDCToken != "" {
		assertion := config.OIDCToken
		credential, err := azidentity.NewClientAssertionCredential(config.TenantID, config.ClientID, func(context.Context) (string, error) {
			return assertion, nil
		}, &azidentity.ClientAssertionCredentialOptions{ClientOptions: identityClientOptions})
		if err != nil {
			return nil, fmt.Errorf("create OIDC client assertion credential: %w", err)
		}
		return credential, nil
	}
	credential, err := azidentity.NewClientSecretCredential(config.TenantID, config.ClientID, config.ClientSecret, &azidentity.ClientSecretCredentialOptions{ClientOptions: identityClientOptions})
	if err != nil {
		return nil, fmt.Errorf("create client secret credential: %w", err)
	}
	return credential, nil
}

func clientOptions(httpClient *http.Client) azcore.ClientOptions {
	options := azcore.ClientOptions{}
	if httpClient != nil {
		options.Transport = httpClient
	}
	return options
}

// fetchGitHubActionsOIDCAssertion implements GitHub's documented environment
// variable protocol. GitHub provides a JavaScript Actions toolkit but no
// general-purpose Go client; token exchange with Entra remains delegated to
// azidentity.ClientAssertionCredential.
func fetchGitHubActionsOIDCAssertion(ctx context.Context, httpClient *http.Client, requestURL, requestToken string) (string, error) {
	parsed, err := url.ParseRequestURI(requestURL)
	if err != nil || !parsed.IsAbs() || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil {
		return "", fmt.Errorf("GitHub Actions OIDC request URL must be an absolute HTTPS URL without user information")
	}
	query := parsed.Query()
	query.Set("audience", DefaultOIDCAudience)
	parsed.RawQuery = query.Encode()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, parsed.String(), nil)
	if err != nil {
		return "", fmt.Errorf("create OIDC assertion request: %w", err)
	}
	request.Header.Set("Authorization", "Bearer "+requestToken)
	response, err := httpClient.Do(request)
	if err != nil {
		return "", fmt.Errorf("request OIDC assertion: %w", err)
	}
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return "", fmt.Errorf("OIDC assertion endpoint returned HTTP %d", response.StatusCode)
	}
	var payload struct {
		Value string `json:"value"`
	}
	if err := json.NewDecoder(io.LimitReader(response.Body, 1024*1024)).Decode(&payload); err != nil {
		return "", fmt.Errorf("decode OIDC assertion response: %w", err)
	}
	if payload.Value == "" {
		return "", fmt.Errorf("OIDC assertion endpoint returned an empty token")
	}
	return payload.Value, nil
}
