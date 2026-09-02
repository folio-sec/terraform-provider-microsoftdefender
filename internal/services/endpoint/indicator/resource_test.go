package indicator

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"

	indicatorclient "github.com/folio-sec/terraform-provider-microsoftdefender/internal/client/endpoint/indicator"
	providertypes "github.com/folio-sec/terraform-provider-microsoftdefender/internal/types"
	"github.com/hashicorp/terraform-plugin-framework-timetypes/timetypes"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	resourceschema "github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-go/tftypes"
)

const testSHA256 = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

type fakeAPI struct {
	submit func(context.Context, indicatorclient.Indicator) (indicatorclient.Indicator, error)
	find   func(context.Context, string) ([]indicatorclient.Indicator, error)
	delete func(context.Context, string) error
}

func (f *fakeAPI) Submit(ctx context.Context, value indicatorclient.Indicator) (indicatorclient.Indicator, error) {
	return f.submit(ctx, value)
}
func (f *fakeAPI) FindByValue(ctx context.Context, value string) ([]indicatorclient.Indicator, error) {
	return f.find(ctx, value)
}
func (f *fakeAPI) Delete(ctx context.Context, id string) error { return f.delete(ctx, id) }

func TestResourceMetadataSchemaAndLifecycle(t *testing.T) {
	t.Parallel()
	subject := NewResource()
	var metadata resource.MetadataResponse
	subject.Metadata(context.Background(), resource.MetadataRequest{ProviderTypeName: "microsoftdefender"}, &metadata)
	if metadata.TypeName != "microsoftdefender_indicator" {
		t.Fatalf("type = %q", metadata.TypeName)
	}
	schemaValue := resourceSchema(t, subject)
	for _, name := range []string{
		"id", "indicator_value", "indicator_type", "action", "title", "description", "application", "external_id",
		"expiration_time", "severity", "recommended_actions", "educate_url", "rbac_group_names", "rbac_group_ids",
		"generate_alert", "source_type", "created_by_source", "created_by", "last_updated_by",
		"creation_time_date_time_utc", "last_update_time",
	} {
		if schemaValue.Attributes[name] == nil {
			t.Errorf("missing attribute %s", name)
		}
	}
	groups := schemaValue.Attributes["rbac_group_names"].(resourceschema.SetAttribute)
	if groups.Required || !groups.Optional || !groups.Computed || groups.Default == nil || groups.ElementType != types.StringType {
		t.Errorf("rbac_group_names = %#v", groups)
	}
	for _, name := range []string{"indicator_value", "indicator_type", "application"} {
		attribute := schemaValue.Attributes[name].(resourceschema.StringAttribute)
		if len(attribute.PlanModifiers) == 0 {
			t.Errorf("%s does not require replacement", name)
			continue
		}
		var response planmodifier.StringResponse
		attribute.PlanModifiers[0].PlanModifyString(context.Background(), planmodifier.StringRequest{
			State: tfsdk.State{Raw: tftypes.NewValue(tftypes.String, "old")}, Plan: tfsdk.Plan{Raw: tftypes.NewValue(tftypes.String, "new")},
			StateValue: types.StringValue("old"), PlanValue: types.StringValue("new"), ConfigValue: types.StringValue("new"),
		}, &response)
		if !response.RequiresReplace {
			t.Errorf("%s lifecycle did not require replacement", name)
		}
	}
}

func TestValidationAndHashNormalization(t *testing.T) {
	t.Parallel()
	valid := testModel(t)
	if diagnostics := validateModel(valid); diagnostics.HasError() {
		t.Fatalf("valid model: %v", diagnostics)
	}
	invalid := valid
	invalid.IndicatorValue = providertypes.LowerStringValueOf("xyz")
	if diagnostics := validateModel(invalid); !diagnostics.HasError() {
		t.Fatal("invalid SHA256 accepted")
	}
	audit := valid
	audit.Action = types.StringValue("Audit")
	audit.GenerateAlert = types.BoolValue(false)
	if diagnostics := validateModel(audit); !diagnostics.HasError() {
		t.Fatal("Audit without generate_alert accepted")
	}
	educateURL := valid
	educateURL.EducateURL = types.StringValue("https://support.example.test/indicator")
	if diagnostics := validateModel(educateURL); !diagnostics.HasError() {
		t.Fatal("educate_url accepted for a non-URL Indicator")
	}
	educateURL.IndicatorType = types.StringValue("Url")
	educateURL.IndicatorValue = providertypes.LowerStringValueOf("https://example.test/path")
	educateURL.Action = types.StringValue("Warn")
	if diagnostics := validateModel(educateURL); diagnostics.HasError() {
		t.Fatalf("valid educate_url configuration: %v", diagnostics)
	}
	value, diagnostics := (providertypes.LowerStringType{}).ValueFromString(context.Background(), types.StringValue(strings.ToUpper(testSHA256)))
	if diagnostics.HasError() || value.(providertypes.LowerStringValue).ValueString() != testSHA256 {
		t.Fatalf("normalized value = %#v, diagnostics = %v", value, diagnostics)
	}
	urlValue, diagnostics := (providertypes.LowerStringType{}).ValueFromString(context.Background(), types.StringValue("https://Example.test/CaseSensitive"))
	if diagnostics.HasError() || urlValue.(providertypes.LowerStringValue).ValueString() != "https://Example.test/CaseSensitive" {
		t.Fatalf("non-hash value changed: %#v", urlValue)
	}
}

func TestCreateSavesIDAndNormalizesRequest(t *testing.T) {
	t.Parallel()
	finds := 0
	submits := 0
	subject := &indicatorResource{client: &fakeAPI{
		find: func(_ context.Context, value string) ([]indicatorclient.Indicator, error) {
			finds++
			if value != testSHA256 {
				t.Errorf("find value = %q", value)
			}
			return nil, nil
		},
		submit: func(_ context.Context, value indicatorclient.Indicator) (indicatorclient.Indicator, error) {
			submits++
			if value.IndicatorValue != testSHA256 || value.Action != "Allowed" || len(value.RBACGroupNames) != 0 {
				t.Errorf("submitted = %#v", value)
			}
			result := value
			result.ID = "api-1"
			return result, nil
		},
	}}
	request, response := createData(t, subject, testModel(t))
	subject.Create(context.Background(), request, response)
	if response.Diagnostics.HasError() {
		t.Fatal(response.Diagnostics)
	}
	state := getState(t, response.State)
	if state.ID.ValueString() != "api-1" || state.IndicatorValue.ValueString() != testSHA256 || finds != 1 || submits != 1 {
		t.Fatalf("state = %#v, finds = %d submits = %d", state, finds, submits)
	}
}

func TestCreateResolvesAmbiguousPost(t *testing.T) {
	t.Parallel()
	finds := 0
	subject := &indicatorResource{client: &fakeAPI{
		find: func(context.Context, string) ([]indicatorclient.Indicator, error) {
			finds++
			if finds == 1 {
				return nil, nil
			}
			return []indicatorclient.Indicator{testIndicator()}, nil
		},
		submit: func(context.Context, indicatorclient.Indicator) (indicatorclient.Indicator, error) {
			return indicatorclient.Indicator{}, errors.New("connection reset")
		},
	}}
	request, response := createData(t, subject, testModel(t))
	subject.Create(context.Background(), request, response)
	if response.Diagnostics.HasError() || getState(t, response.State).ID.ValueString() != "api-1" {
		t.Fatalf("diagnostics = %v", response.Diagnostics)
	}
}

func TestCreateDoesNotAdoptDifferentIndicatorAfterAmbiguousPost(t *testing.T) {
	t.Parallel()
	finds := 0
	different := testIndicator()
	different.Action = "Block"
	subject := &indicatorResource{client: &fakeAPI{
		find: func(context.Context, string) ([]indicatorclient.Indicator, error) {
			finds++
			if finds == 1 {
				return nil, nil
			}
			return []indicatorclient.Indicator{different}, nil
		},
		submit: func(context.Context, indicatorclient.Indicator) (indicatorclient.Indicator, error) {
			return indicatorclient.Indicator{}, errors.New("connection reset")
		},
	}}
	request, response := createData(t, subject, testModel(t))
	subject.Create(context.Background(), request, response)
	if !response.Diagnostics.HasError() || !response.State.Raw.IsNull() {
		t.Fatalf("diagnostics = %v, state = %v", response.Diagnostics, response.State.Raw)
	}
	if !strings.Contains(response.Diagnostics.Errors()[0].Summary(), "ownership") {
		t.Fatalf("diagnostics = %v", response.Diagnostics)
	}
}

func TestCreateDoesNotVerifyRequestNotSentError(t *testing.T) {
	t.Parallel()
	finds := 0
	subject := &indicatorResource{client: &fakeAPI{
		find: func(context.Context, string) ([]indicatorclient.Indicator, error) {
			finds++
			return nil, nil
		},
		submit: func(context.Context, indicatorclient.Indicator) (indicatorclient.Indicator, error) {
			return indicatorclient.Indicator{}, &indicatorclient.RequestNotSentError{Err: errors.New("token acquisition failed")}
		},
	}}
	request, response := createData(t, subject, testModel(t))
	subject.Create(context.Background(), request, response)
	if !response.Diagnostics.HasError() || finds != 1 {
		t.Fatalf("diagnostics = %v, finds = %d", response.Diagnostics, finds)
	}
	if response.Diagnostics.Errors()[0].Summary() != "Unable to create Indicator" {
		t.Fatalf("diagnostics = %v", response.Diagnostics)
	}
}

func TestReadDriftNotFoundAndIDMismatch(t *testing.T) {
	t.Parallel()
	createdBy := "principal-1"
	creationTime := "2026-09-01T00:00:00Z"
	for name, results := range map[string][]indicatorclient.Indicator{
		"drift": {{
			ID: "api-1", IndicatorValue: testSHA256, IndicatorType: "FileSha256", Action: "Block", Title: "drifted", Description: "changed",
			Severity: "High", RBACGroupNames: []string{"B", "A"}, RBACGroupIDs: []string{"group-1"}, GenerateAlert: true,
			CreatedBy: &createdBy, CreationTimeDateTimeUTC: &creationTime,
		}},
		"not found": nil,
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			subject := &indicatorResource{client: &fakeAPI{find: func(context.Context, string) ([]indicatorclient.Indicator, error) { return results, nil }}}
			request, response := readData(t, subject, testModel(t))
			subject.Read(context.Background(), request, response)
			if response.Diagnostics.HasError() {
				t.Fatal(response.Diagnostics)
			}
			if name == "not found" {
				if !response.State.Raw.IsNull() {
					t.Fatalf("state = %v, want removed", response.State.Raw)
				}
				return
			}
			state := getState(t, response.State)
			if state.Action.ValueString() != "Block" || state.Title.ValueString() != "drifted" || state.Severity.ValueString() != "High" ||
				!state.GenerateAlert.ValueBool() || state.CreatedBy.ValueString() != createdBy ||
				state.CreationTimeDateTimeUTC.ValueString() != creationTime || state.RBACGroupIDs.IsNull() {
				t.Fatalf("state = %#v", state)
			}
		})
	}
}

func TestReadRejectsIDMismatchWithoutRemovingState(t *testing.T) {
	t.Parallel()
	subject := &indicatorResource{client: &fakeAPI{find: func(context.Context, string) ([]indicatorclient.Indicator, error) {
		return []indicatorclient.Indicator{{ID: "other", IndicatorValue: testSHA256}}, nil
	}}}
	request, response := readData(t, subject, testModel(t))
	subject.Read(context.Background(), request, response)
	if !response.Diagnostics.HasError() {
		t.Fatal("API ID mismatch accepted")
	}
	if response.State.Raw.IsNull() {
		t.Fatal("state removed after API ID mismatch")
	}
}

func TestSetStatePreservesEquivalentExpirationTime(t *testing.T) {
	t.Parallel()
	model := testModel(t)
	model.ExpirationTime = timetypes.NewRFC3339ValueMust("2026-09-01T09:00:00+09:00")
	apiTime := "2026-09-01T00:00:00Z"
	value := testIndicator()
	value.ExpirationTime = &apiTime
	var diagnostics diag.Diagnostics
	setState(context.Background(), &model, value, &diagnostics)
	if diagnostics.HasError() {
		t.Fatal(diagnostics)
	}
	if got := model.ExpirationTime.ValueString(); got != "2026-09-01T09:00:00+09:00" {
		t.Fatalf("expiration_time = %q", got)
	}
}

func TestReadRejectsMultipleMatches(t *testing.T) {
	t.Parallel()
	first, second := testIndicator(), testIndicator()
	second.ID = "api-2"
	subject := &indicatorResource{client: &fakeAPI{find: func(context.Context, string) ([]indicatorclient.Indicator, error) {
		return []indicatorclient.Indicator{first, second}, nil
	}}}
	request, response := readData(t, subject, testModel(t))
	subject.Read(context.Background(), request, response)
	if !response.Diagnostics.HasError() {
		t.Fatal("multiple matches accepted")
	}
}

func TestUpdatePostsAndRefreshesState(t *testing.T) {
	t.Parallel()
	submits := 0
	subject := &indicatorResource{client: &fakeAPI{submit: func(_ context.Context, value indicatorclient.Indicator) (indicatorclient.Indicator, error) {
		submits++
		value.Title = "updated by API"
		return value, nil
	}}}
	request, response := updateData(t, subject, testModel(t))
	subject.Update(context.Background(), request, response)
	if response.Diagnostics.HasError() || submits != 1 || getState(t, response.State).Title.ValueString() != "updated by API" {
		t.Fatalf("diagnostics = %v, submits = %d", response.Diagnostics, submits)
	}
}

func TestEducateURLRoundTrip(t *testing.T) {
	t.Parallel()
	model := testModel(t)
	model.IndicatorValue = providertypes.LowerStringValueOf("https://example.test/path")
	model.IndicatorType = types.StringValue("Url")
	model.Action = types.StringValue("Warn")
	model.EducateURL = types.StringValue("https://support.example.test/indicator")
	subject := &indicatorResource{client: &fakeAPI{submit: func(_ context.Context, value indicatorclient.Indicator) (indicatorclient.Indicator, error) {
		if value.EducateURL == nil || *value.EducateURL != model.EducateURL.ValueString() {
			t.Errorf("educate URL = %#v", value.EducateURL)
		}
		return value, nil
	}}}
	request, response := updateData(t, subject, model)
	subject.Update(context.Background(), request, response)
	if response.Diagnostics.HasError() || getState(t, response.State).EducateURL.ValueString() != model.EducateURL.ValueString() {
		t.Fatalf("diagnostics = %v", response.Diagnostics)
	}
}

func TestDelete204And404(t *testing.T) {
	t.Parallel()
	for name, deleteErr := range map[string]error{"204": nil, "404": nil} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			deletes := 0
			subject := &indicatorResource{client: &fakeAPI{delete: func(_ context.Context, id string) error {
				deletes++
				if id != "api-1" {
					t.Errorf("id = %q", id)
				}
				return deleteErr
			}}}
			request, response := deleteData(t, subject, testModel(t))
			subject.Delete(context.Background(), request, response)
			if response.Diagnostics.HasError() || deletes != 1 {
				t.Fatalf("diagnostics = %v deletes = %d", response.Diagnostics, deletes)
			}
		})
	}
}

func TestSetOrderAndImport(t *testing.T) {
	t.Parallel()
	left, diagnostics := types.SetValueFrom(context.Background(), types.StringType, []string{"A", "B"})
	if diagnostics.HasError() {
		t.Fatal(diagnostics)
	}
	right, diagnostics := types.SetValueFrom(context.Background(), types.StringType, []string{"B", "A"})
	if diagnostics.HasError() || !left.Equal(right) {
		t.Fatalf("sets are not equal: %v %v", left, right)
	}
	subject := &indicatorResource{}
	schemaValue := resourceSchema(t, subject)
	ctx := context.Background()
	response := &resource.ImportStateResponse{State: tfsdk.State{Raw: tftypes.NewValue(schemaValue.Type().TerraformType(ctx), nil), Schema: schemaValue}}
	subject.ImportState(ctx, resource.ImportStateRequest{ID: strings.ToUpper(testSHA256)}, response)
	if response.Diagnostics.HasError() {
		t.Fatal(response.Diagnostics)
	}
	var imported resourceModel
	response.Diagnostics.Append(response.State.Get(ctx, &imported)...)
	if imported.IndicatorValue.ValueString() != testSHA256 {
		t.Fatalf("imported value = %q", imported.IndicatorValue.ValueString())
	}
	bad := &resource.ImportStateResponse{State: response.State}
	subject.ImportState(ctx, resource.ImportStateRequest{ID: "bad"}, bad)
	if !bad.Diagnostics.HasError() {
		t.Fatal("invalid import accepted")
	}
}

func TestMutationAmbiguityClassification(t *testing.T) {
	t.Parallel()
	if mutationOutcomeMayBeAmbiguous(&indicatorclient.RequestNotSentError{Err: errors.New("token")}) {
		t.Fatal("request-not-sent error classified ambiguous")
	}
	if mutationOutcomeMayBeAmbiguous(&indicatorclient.HTTPError{StatusCode: http.StatusBadRequest}) {
		t.Fatal("400 classified ambiguous")
	}
	if mutationOutcomeMayBeAmbiguous(&indicatorclient.HTTPError{StatusCode: http.StatusTooManyRequests}) {
		t.Fatal("429 classified ambiguous")
	}
	if !mutationOutcomeMayBeAmbiguous(&indicatorclient.HTTPError{StatusCode: http.StatusInternalServerError}) {
		t.Fatal("500 classified unambiguous")
	}
	if !mutationOutcomeMayBeAmbiguous(errors.New("connection reset")) {
		t.Fatal("transport error classified unambiguous")
	}
}

func testModel(t *testing.T) resourceModel {
	t.Helper()
	groups, diagnostics := types.SetValueFrom(context.Background(), types.StringType, []string{})
	if diagnostics.HasError() {
		t.Fatal(diagnostics)
	}
	return resourceModel{
		ID: types.StringValue("api-1"), IndicatorValue: providertypes.LowerStringValueOf(testSHA256), IndicatorType: types.StringValue("FileSha256"),
		Action: types.StringValue("Allowed"), Title: types.StringValue("Example Application"), Description: types.StringValue("Approved"), Application: types.StringValue("Example Application"),
		ExpirationTime: timetypes.NewRFC3339Null(), Severity: types.StringValue("Informational"), RecommendedActions: types.StringNull(), EducateURL: types.StringNull(),
		RBACGroupNames: groups, GenerateAlert: types.BoolValue(false),
		ExternalID: types.StringNull(), SourceType: types.StringNull(), CreatedBySource: types.StringNull(), CreatedBy: types.StringNull(), LastUpdatedBy: types.StringNull(),
		CreationTimeDateTimeUTC: timetypes.NewRFC3339Null(), LastUpdateTime: timetypes.NewRFC3339Null(), RBACGroupIDs: types.SetNull(types.StringType),
	}
}

func testIndicator() indicatorclient.Indicator {
	application := "Example Application"
	return indicatorclient.Indicator{ID: "api-1", IndicatorValue: testSHA256, IndicatorType: "FileSha256", Action: "Allowed", Title: "Example Application", Description: "Approved", Application: &application, Severity: "Informational", RBACGroupNames: []string{}, GenerateAlert: false}
}

func resourceSchema(t *testing.T, subject resource.Resource) resourceschema.Schema {
	t.Helper()
	var response resource.SchemaResponse
	subject.Schema(context.Background(), resource.SchemaRequest{}, &response)
	if response.Diagnostics.HasError() {
		t.Fatal(response.Diagnostics)
	}
	return response.Schema
}

func createData(t *testing.T, subject resource.Resource, model resourceModel) (resource.CreateRequest, *resource.CreateResponse) {
	t.Helper()
	schemaValue := resourceSchema(t, subject)
	ctx := context.Background()
	plan := tfsdk.Plan{Raw: tftypes.NewValue(schemaValue.Type().TerraformType(ctx), nil), Schema: schemaValue}
	model.ID = types.StringUnknown()
	if diagnostics := plan.Set(ctx, &model); diagnostics.HasError() {
		t.Fatal(diagnostics)
	}
	return resource.CreateRequest{Plan: plan}, &resource.CreateResponse{State: tfsdk.State{Raw: tftypes.NewValue(schemaValue.Type().TerraformType(ctx), nil), Schema: schemaValue}}
}

func readData(t *testing.T, subject resource.Resource, model resourceModel) (resource.ReadRequest, *resource.ReadResponse) {
	t.Helper()
	schemaValue := resourceSchema(t, subject)
	ctx := context.Background()
	state := tfsdk.State{Raw: tftypes.NewValue(schemaValue.Type().TerraformType(ctx), nil), Schema: schemaValue}
	if diagnostics := state.Set(ctx, &model); diagnostics.HasError() {
		t.Fatal(diagnostics)
	}
	return resource.ReadRequest{State: state}, &resource.ReadResponse{State: state}
}

func updateData(t *testing.T, subject resource.Resource, model resourceModel) (resource.UpdateRequest, *resource.UpdateResponse) {
	t.Helper()
	schemaValue := resourceSchema(t, subject)
	ctx := context.Background()
	plan := tfsdk.Plan{Raw: tftypes.NewValue(schemaValue.Type().TerraformType(ctx), nil), Schema: schemaValue}
	state := tfsdk.State{Raw: tftypes.NewValue(schemaValue.Type().TerraformType(ctx), nil), Schema: schemaValue}
	if diagnostics := state.Set(ctx, &model); diagnostics.HasError() {
		t.Fatal(diagnostics)
	}
	model.ID = types.StringUnknown()
	if diagnostics := plan.Set(ctx, &model); diagnostics.HasError() {
		t.Fatal(diagnostics)
	}
	return resource.UpdateRequest{Plan: plan, State: state}, &resource.UpdateResponse{State: tfsdk.State{Raw: tftypes.NewValue(schemaValue.Type().TerraformType(ctx), nil), Schema: schemaValue}}
}

func deleteData(t *testing.T, subject resource.Resource, model resourceModel) (resource.DeleteRequest, *resource.DeleteResponse) {
	t.Helper()
	readRequest, _ := readData(t, subject, model)
	return resource.DeleteRequest{State: readRequest.State}, &resource.DeleteResponse{}
}

func getState(t *testing.T, state tfsdk.State) resourceModel {
	t.Helper()
	var model resourceModel
	if diagnostics := state.Get(context.Background(), &model); diagnostics.HasError() {
		t.Fatal(diagnostics)
	}
	return model
}
