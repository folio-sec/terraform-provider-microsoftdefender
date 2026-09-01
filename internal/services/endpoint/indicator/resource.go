package indicator

import (
	"context"
	"fmt"
	"slices"

	"github.com/folio-sec/terraform-provider-microsoftdefender/internal/client"
	indicatorclient "github.com/folio-sec/terraform-provider-microsoftdefender/internal/client/endpoint/indicator"
	providertypes "github.com/folio-sec/terraform-provider-microsoftdefender/internal/types"
	"github.com/folio-sec/terraform-provider-microsoftdefender/internal/validation"
	"github.com/hashicorp/terraform-plugin-framework-timetypes/timetypes"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/booldefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/setdefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringdefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

var (
	_ resource.Resource                   = &indicatorResource{}
	_ resource.ResourceWithImportState    = &indicatorResource{}
	_ resource.ResourceWithValidateConfig = &indicatorResource{}
)

type api interface {
	Submit(context.Context, indicatorclient.Indicator) (indicatorclient.Indicator, error)
	FindByValue(context.Context, string) ([]indicatorclient.Indicator, error)
	Delete(context.Context, string) error
}

type indicatorResource struct{ client api }

func NewResource() resource.Resource { return &indicatorResource{} }

func (r *indicatorResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_indicator"
}

func (r *indicatorResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	replace := []planmodifier.String{stringplanmodifier.RequiresReplace()}
	markdownDescription := "Manages an Indicator through the Microsoft Defender for Endpoint native Indicator API.\n\n" +
		"## Operational considerations\n\n" +
		"- This resource requires a Microsoft Entra application with the `WindowsDefenderATP / Ti.ReadWrite.All` application permission and tenant administrator consent.\n" +
		"- Import accepts a `FileSha256` `indicator_value` (64 hexadecimal characters), not the Defender API ID.\n" +
		"- Creating an Indicator through the API and enforcing it on endpoints are separate concerns. Follow Microsoft's [file Indicator prerequisites](https://learn.microsoft.com/en-us/defender-endpoint/indicator-file#prerequisites). For file blocking, Microsoft specifically requires **Settings > Endpoints > General > Advanced features > Allow or block file** to be enabled.\n" +
		"- A file hash Indicator whose action is `Allowed` can take precedence over an Attack Surface Reduction or antivirus block in Microsoft's published [policy conflict order](https://learn.microsoft.com/en-us/defender-endpoint/indicator-file#policy-conflict-handling-for-file-indicators). It does not override a Windows Defender Application Control or AppLocker enforce-mode block. A blocking certificate Indicator always takes precedence over an allow file-hash Indicator.\n" +
		"- The Indicator APIs are limited to 100 calls per minute and 1,500 calls per hour, with at most 15,000 active Indicators per tenant. Safe GET requests retry bounded 429 and transient server responses; mutations are not retried automatically. See the official [API limitations](https://learn.microsoft.com/en-us/defender-endpoint/api/post-ti-indicator#limitations)."
	resp.Schema = schema.Schema{
		MarkdownDescription: markdownDescription,
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Description: "Microsoft Defender Indicator API ID.",
				Computed:    true,
			},
			"indicator_value": schema.StringAttribute{
				CustomType:    providertypes.LowerStringType{},
				Description:   "Indicator value. File hashes are normalized to lowercase. Changing it replaces the resource.",
				Required:      true,
				PlanModifiers: replace,
			},
			"indicator_type": schema.StringAttribute{
				MarkdownDescription: "Indicator type. Supported values:\n\n```text\nFileSha1\nFileMd5\nCertificateThumbprint\nFileSha256\nIpAddress\nDomainName\nUrl\n```",
				Required:            true,
				Validators: []validator.String{
					stringvalidator.OneOf(
						"FileSha1",
						"FileMd5",
						"CertificateThumbprint",
						"FileSha256",
						"IpAddress",
						"DomainName",
						"Url",
					),
				},
				PlanModifiers: replace,
			},
			"action": schema.StringAttribute{
				MarkdownDescription: "Current Indicator action. Supported values:\n\n```text\nAllowed\nAudit\nBlock\nBlockAndRemediate\nWarn\n```\n\nThe legacy `Alert` and `AlertAndBlock` actions are rejected.",
				Required:            true,
				Validators: []validator.String{
					stringvalidator.OneOf(
						"Allowed",
						"Audit",
						"Block",
						"BlockAndRemediate",
						"Warn",
					),
				},
			},
			"title": schema.StringAttribute{
				Description: "Indicator alert title.",
				Required:    true,
			},
			"description": schema.StringAttribute{
				Description: "Indicator description.",
				Required:    true,
			},
			"application": schema.StringAttribute{
				Description:   "User-friendly application name. The API only applies it when creating an Indicator, so changing it replaces the resource.",
				Optional:      true,
				PlanModifiers: replace,
			},
			"external_id": schema.StringAttribute{
				Description: "API-reported external correlation ID.",
				Computed:    true,
			},
			"expiration_time": schema.StringAttribute{
				CustomType:  timetypes.RFC3339Type{},
				Description: "Optional RFC3339 expiration time.",
				Optional:    true,
			},
			"severity": schema.StringAttribute{
				MarkdownDescription: "Indicator severity. Supported values:\n\n```text\nInformational\nLow\nMedium\nHigh\n```",
				Optional:            true,
				Computed:            true,
				Default:             stringdefault.StaticString("Informational"),
				Validators: []validator.String{
					stringvalidator.OneOf(
						"Informational",
						"Low",
						"Medium",
						"High",
					),
				},
			},
			"recommended_actions": schema.StringAttribute{
				Description: "Recommended actions displayed with Indicator alerts.",
				Optional:    true,
			},
			"educate_url": schema.StringAttribute{
				Description: "Custom notification or support URL. Supported by the API for URL Indicators with Block or Warn actions.",
				Optional:    true,
			},
			"rbac_group_names": schema.SetAttribute{
				MarkdownDescription: "RBAC device group names. **Warning:** An empty or omitted set applies the Indicator to all Defender devices in the tenant.",
				Optional:            true,
				Computed:            true,
				ElementType:         types.StringType,
				Default:             setdefault.StaticValue(types.SetValueMust(types.StringType, nil)),
			},
			"generate_alert": schema.BoolAttribute{
				Description: "Whether the Indicator generates an alert. Must be true for Audit.",
				Optional:    true,
				Computed:    true,
				Default:     booldefault.StaticBool(false),
			},
			"source_type": schema.StringAttribute{
				Description: "API-reported source type.",
				Computed:    true,
			},
			"created_by_source": schema.StringAttribute{
				Description: "API-reported source that created the Indicator.",
				Computed:    true,
			},
			"created_by": schema.StringAttribute{
				Description: "API-reported identity that created the Indicator.",
				Computed:    true,
			},
			"last_updated_by": schema.StringAttribute{
				Description: "API-reported identity that last updated the Indicator.",
				Computed:    true,
			},
			"creation_time_date_time_utc": schema.StringAttribute{
				CustomType:  timetypes.RFC3339Type{},
				Description: "API-reported Indicator creation time.",
				Computed:    true,
			},
			"last_update_time": schema.StringAttribute{
				CustomType:  timetypes.RFC3339Type{},
				Description: "API-reported last update time.",
				Computed:    true,
			},
			"rbac_group_ids": schema.SetAttribute{
				Description: "API-reported RBAC device group IDs.",
				Computed:    true,
				ElementType: types.StringType,
			},
		},
	}
}

func (r *indicatorResource) ValidateConfig(ctx context.Context, req resource.ValidateConfigRequest, resp *resource.ValidateConfigResponse) {
	var config resourceModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
	if resp.Diagnostics.HasError() {
		return
	}
	resp.Diagnostics.Append(validateModel(config)...)
}

func validateModel(model resourceModel) diag.Diagnostics {
	var diagnostics diag.Diagnostics
	if !model.IndicatorValue.IsNull() && !model.IndicatorValue.IsUnknown() && !model.IndicatorType.IsNull() && !model.IndicatorType.IsUnknown() {
		lengths := map[string]int{"FileSha256": validation.SHA256HexLength, "FileSha1": validation.SHA1HexLength, "FileMd5": validation.MD5HexLength}
		if length, isHash := lengths[model.IndicatorType.ValueString()]; isHash {
			value := model.IndicatorValue.ValueString()
			if !validation.IsHexHash(value, length) {
				diagnostics.AddAttributeError(path.Root("indicator_value"), "Invalid file hash", fmt.Sprintf("%s must be exactly %d hexadecimal characters.", model.IndicatorType.ValueString(), length))
			}
		}
	}
	if !model.Action.IsNull() && !model.Action.IsUnknown() && model.Action.ValueString() == "Audit" && !model.GenerateAlert.IsUnknown() && (model.GenerateAlert.IsNull() || !model.GenerateAlert.ValueBool()) {
		diagnostics.AddAttributeError(path.Root("generate_alert"), "Audit requires alert generation", "generate_alert must be true when action is Audit.")
	}
	if !model.EducateURL.IsNull() && !model.EducateURL.IsUnknown() &&
		!model.IndicatorType.IsNull() && !model.IndicatorType.IsUnknown() &&
		!model.Action.IsNull() && !model.Action.IsUnknown() &&
		(model.IndicatorType.ValueString() != "Url" || !slices.Contains([]string{"Block", "Warn"}, model.Action.ValueString())) {
		diagnostics.AddAttributeError(path.Root("educate_url"), "Unsupported educate URL", "educate_url is supported only for Url Indicators whose action is Block or Warn.")
	}
	return diagnostics
}

func (r *indicatorResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}
	configured, ok := req.ProviderData.(*client.Client)
	if !ok {
		resp.Diagnostics.AddError("Unexpected provider data", fmt.Sprintf("Expected *client.Client, got %T", req.ProviderData))
		return
	}
	r.client = configured.Indicator
}
