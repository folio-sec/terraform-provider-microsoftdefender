package provider

import (
	"context"
	"fmt"
	"os"

	"github.com/folio-sec/terraform-provider-microsoftdefender/internal/client"
	indicatorservice "github.com/folio-sec/terraform-provider-microsoftdefender/internal/services/endpoint/indicator"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/provider"
	"github.com/hashicorp/terraform-plugin-framework/provider/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

//go:generate go run github.com/hashicorp/terraform-plugin-docs/cmd/tfplugindocs generate --provider-name microsoftdefender --provider-dir ../..

var _ provider.Provider = &MicrosoftDefenderProvider{}

type MicrosoftDefenderProvider struct{ version string }

type providerModel struct {
	TenantID          types.String `tfsdk:"tenant_id"`
	ClientID          types.String `tfsdk:"client_id"`
	ClientSecret      types.String `tfsdk:"client_secret"`
	OIDCToken         types.String `tfsdk:"oidc_token"`
	OIDCTokenFilePath types.String `tfsdk:"oidc_token_file_path"`
}

func New(version string) func() provider.Provider {
	return func() provider.Provider { return &MicrosoftDefenderProvider{version: version} }
}

func (p *MicrosoftDefenderProvider) Metadata(_ context.Context, _ provider.MetadataRequest, resp *provider.MetadataResponse) {
	resp.TypeName = "microsoftdefender"
	resp.Version = p.version
}

func (p *MicrosoftDefenderProvider) Schema(_ context.Context, _ provider.SchemaRequest, resp *provider.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Manage Microsoft Defender for Endpoint native API resources.",
		Attributes: map[string]schema.Attribute{
			"tenant_id": schema.StringAttribute{
				Description: "Microsoft Entra tenant ID. May also be set with MICROSOFTDEFENDER_TENANT_ID.",
				Optional:    true,
			},
			"client_id": schema.StringAttribute{
				Description: "Microsoft Entra application (client) ID. May also be set with MICROSOFTDEFENDER_CLIENT_ID.",
				Optional:    true,
			},
			"client_secret": schema.StringAttribute{
				Description: "Microsoft Entra client secret. Prefer MICROSOFTDEFENDER_CLIENT_SECRET instead of configuration.",
				Optional:    true,
				Sensitive:   true,
			},
			"oidc_token": schema.StringAttribute{
				Description: "OIDC workload identity token. Prefer MICROSOFTDEFENDER_OIDC_TOKEN instead of configuration.",
				Optional:    true,
				Sensitive:   true,
			},
			"oidc_token_file_path": schema.StringAttribute{
				Description: "Path to a file containing an OIDC workload identity token. May also be set with MICROSOFTDEFENDER_OIDC_TOKEN_FILE_PATH or AZURE_FEDERATED_TOKEN_FILE.",
				Optional:    true,
			},
		},
	}
}

func (p *MicrosoftDefenderProvider) Configure(ctx context.Context, req provider.ConfigureRequest, resp *provider.ConfigureResponse) {
	var config providerModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
	if resp.Diagnostics.HasError() {
		return
	}
	for name, value := range map[string]types.String{"tenant_id": config.TenantID, "client_id": config.ClientID, "client_secret": config.ClientSecret, "oidc_token": config.OIDCToken, "oidc_token_file_path": config.OIDCTokenFilePath} {
		if value.IsUnknown() {
			resp.Diagnostics.AddError("Unknown provider configuration", fmt.Sprintf("%s must be known during provider configuration.", name))
		}
	}
	if resp.Diagnostics.HasError() {
		return
	}
	clientConfig := client.Config{
		TenantID:          configuredValueWithFallback(config.TenantID, "MICROSOFTDEFENDER_TENANT_ID", "AZURE_TENANT_ID"),
		ClientID:          configuredValueWithFallback(config.ClientID, "MICROSOFTDEFENDER_CLIENT_ID", "AZURE_CLIENT_ID"),
		ClientSecret:      configuredValue(config.ClientSecret, "MICROSOFTDEFENDER_CLIENT_SECRET"),
		OIDCToken:         configuredValue(config.OIDCToken, "MICROSOFTDEFENDER_OIDC_TOKEN"),
		OIDCTokenFilePath: configuredValueWithFallback(config.OIDCTokenFilePath, "MICROSOFTDEFENDER_OIDC_TOKEN_FILE_PATH", "AZURE_FEDERATED_TOKEN_FILE"),
	}
	if clientConfig.ClientSecret == "" && clientConfig.OIDCToken == "" && clientConfig.OIDCTokenFilePath == "" {
		clientConfig.GitHubOIDCRequestURL = configuredEnvironment("ACTIONS_ID_TOKEN_REQUEST_URL")
		clientConfig.GitHubOIDCRequestToken = configuredEnvironment("ACTIONS_ID_TOKEN_REQUEST_TOKEN")
	}
	configured, err := client.New(clientConfig)
	if err != nil {
		resp.Diagnostics.AddError("Unable to configure Microsoft Defender client", fmt.Sprintf("Invalid provider configuration: %s", err))
		return
	}
	resp.ResourceData = configured
}

func configuredEnvironment(environmentVariables ...string) string {
	for _, environmentVariable := range environmentVariables {
		if configured := os.Getenv(environmentVariable); configured != "" {
			return configured
		}
	}
	return ""
}

func (p *MicrosoftDefenderProvider) Resources(context.Context) []func() resource.Resource {
	return []func() resource.Resource{indicatorservice.NewResource}
}

func (p *MicrosoftDefenderProvider) DataSources(context.Context) []func() datasource.DataSource {
	return nil
}

func configuredValue(value types.String, environmentVariable string) string {
	if !value.IsNull() {
		return value.ValueString()
	}
	return os.Getenv(environmentVariable)
}

func configuredValueWithFallback(value types.String, environmentVariables ...string) string {
	if !value.IsNull() {
		return value.ValueString()
	}
	for _, environmentVariable := range environmentVariables {
		if configured := os.Getenv(environmentVariable); configured != "" {
			return configured
		}
	}
	return ""
}
