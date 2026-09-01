package indicator

import (
	"context"
	"slices"
	"strings"

	indicatorclient "github.com/folio-sec/terraform-provider-microsoftdefender/internal/client/endpoint/indicator"
	"github.com/folio-sec/terraform-provider-microsoftdefender/internal/equal"
	providertypes "github.com/folio-sec/terraform-provider-microsoftdefender/internal/types"
	"github.com/folio-sec/terraform-provider-microsoftdefender/internal/validation"
	"github.com/hashicorp/terraform-plugin-framework-timetypes/timetypes"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

type resourceModel struct {
	ID                      types.String                   `tfsdk:"id"`
	IndicatorValue          providertypes.LowerStringValue `tfsdk:"indicator_value"`
	IndicatorType           types.String                   `tfsdk:"indicator_type"`
	Action                  types.String                   `tfsdk:"action"`
	Title                   types.String                   `tfsdk:"title"`
	Description             types.String                   `tfsdk:"description"`
	Application             types.String                   `tfsdk:"application"`
	ExternalID              types.String                   `tfsdk:"external_id"`
	ExpirationTime          timetypes.RFC3339              `tfsdk:"expiration_time"`
	Severity                types.String                   `tfsdk:"severity"`
	RecommendedActions      types.String                   `tfsdk:"recommended_actions"`
	EducateURL              types.String                   `tfsdk:"educate_url"`
	RBACGroupNames          types.Set                      `tfsdk:"rbac_group_names"`
	GenerateAlert           types.Bool                     `tfsdk:"generate_alert"`
	SourceType              types.String                   `tfsdk:"source_type"`
	CreatedBySource         types.String                   `tfsdk:"created_by_source"`
	CreatedBy               types.String                   `tfsdk:"created_by"`
	LastUpdatedBy           types.String                   `tfsdk:"last_updated_by"`
	CreationTimeDateTimeUTC timetypes.RFC3339              `tfsdk:"creation_time_date_time_utc"`
	LastUpdateTime          timetypes.RFC3339              `tfsdk:"last_update_time"`
	RBACGroupIDs            types.Set                      `tfsdk:"rbac_group_ids"`
}

func apiIndicator(ctx context.Context, model resourceModel, diagnostics *diag.Diagnostics) indicatorclient.Indicator {
	groups := make([]string, 0)
	diagnostics.Append(model.RBACGroupNames.ElementsAs(ctx, &groups, false)...)
	slices.Sort(groups)
	return indicatorclient.Indicator{
		IndicatorValue:     model.IndicatorValue.ValueString(),
		IndicatorType:      model.IndicatorType.ValueString(),
		Action:             model.Action.ValueString(),
		Title:              model.Title.ValueString(),
		Description:        model.Description.ValueString(),
		Application:        providertypes.StringPointer(model.Application),
		ExpirationTime:     providertypes.StringPointer(model.ExpirationTime),
		Severity:           model.Severity.ValueString(),
		RecommendedActions: providertypes.StringPointer(model.RecommendedActions),
		EducateURL:         providertypes.StringPointer(model.EducateURL),
		RBACGroupNames:     groups,
		GenerateAlert:      model.GenerateAlert.ValueBool(),
	}
}

func setState(ctx context.Context, model *resourceModel, value indicatorclient.Indicator, diagnostics *diag.Diagnostics) {
	model.ID = types.StringValue(value.ID)
	model.IndicatorValue = providertypes.LowerStringValueOf(value.IndicatorValue)
	model.IndicatorType = types.StringValue(value.IndicatorType)
	model.Action = types.StringValue(value.Action)
	model.Title = types.StringValue(value.Title)
	model.Description = types.StringValue(value.Description)
	model.Application = providertypes.StringValue(value.Application)
	model.ExternalID = providertypes.StringValue(value.ExternalID)
	model.ExpirationTime = stateRFC3339(model.ExpirationTime, value.ExpirationTime, diagnostics)
	model.Severity = types.StringValue(value.Severity)
	model.RecommendedActions = providertypes.StringValue(value.RecommendedActions)
	model.EducateURL = providertypes.StringValue(value.EducateURL)
	model.GenerateAlert = types.BoolValue(value.GenerateAlert)
	model.SourceType = providertypes.StringValue(value.SourceType)
	model.CreatedBySource = providertypes.StringValue(value.CreatedBySource)
	model.CreatedBy = providertypes.StringValue(value.CreatedBy)
	model.LastUpdatedBy = providertypes.StringValue(value.LastUpdatedBy)
	model.CreationTimeDateTimeUTC = stateRFC3339(model.CreationTimeDateTimeUTC, value.CreationTimeDateTimeUTC, diagnostics)
	model.LastUpdateTime = stateRFC3339(model.LastUpdateTime, value.LastUpdateTime, diagnostics)
	set, setDiagnostics := types.SetValueFrom(ctx, types.StringType, value.RBACGroupNames)
	diagnostics.Append(setDiagnostics...)
	model.RBACGroupNames = set
	rbacGroupIDs, rbacGroupIDDiagnostics := types.SetValueFrom(ctx, types.StringType, value.RBACGroupIDs)
	diagnostics.Append(rbacGroupIDDiagnostics...)
	model.RBACGroupIDs = rbacGroupIDs
}

func stateRFC3339(current timetypes.RFC3339, value *string, diagnostics *diag.Diagnostics) timetypes.RFC3339 {
	if value == nil {
		return timetypes.NewRFC3339Null()
	}
	if !current.IsNull() && !current.IsUnknown() && equal.OptionalRFC3339Time(providertypes.StringPointer(current), value) {
		return current
	}
	result, resultDiagnostics := timetypes.NewRFC3339PointerValue(value)
	diagnostics.Append(resultDiagnostics...)
	return result
}

func indicatorValuesEqual(left, right string) bool {
	for _, length := range []int{validation.MD5HexLength, validation.SHA1HexLength, validation.SHA256HexLength} {
		if validation.IsHexHash(left, length) && validation.IsHexHash(right, length) {
			return strings.EqualFold(left, right)
		}
	}
	return left == right
}

func indicatorMismatches(actual, expected indicatorclient.Indicator) []string {
	mismatches := make([]string, 0)
	compareString := func(name, actualValue, expectedValue string) {
		if actualValue != expectedValue {
			mismatches = append(mismatches, name)
		}
	}
	compareString("indicator_type", actual.IndicatorType, expected.IndicatorType)
	compareString("action", actual.Action, expected.Action)
	compareString("title", actual.Title, expected.Title)
	compareString("description", actual.Description, expected.Description)
	compareString("severity", actual.Severity, expected.Severity)
	if !equal.OptionalString(actual.Application, expected.Application) {
		mismatches = append(mismatches, "application")
	}
	if !equal.OptionalRFC3339Time(actual.ExpirationTime, expected.ExpirationTime) {
		mismatches = append(mismatches, "expiration_time")
	}
	if !equal.OptionalString(actual.RecommendedActions, expected.RecommendedActions) {
		mismatches = append(mismatches, "recommended_actions")
	}
	if !equal.OptionalString(actual.EducateURL, expected.EducateURL) {
		mismatches = append(mismatches, "educate_url")
	}
	if !equal.StringSet(actual.RBACGroupNames, expected.RBACGroupNames) {
		mismatches = append(mismatches, "rbac_group_names")
	}
	if actual.GenerateAlert != expected.GenerateAlert {
		mismatches = append(mismatches, "generate_alert")
	}
	return mismatches
}
