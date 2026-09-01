package indicator

import (
	"context"
	"errors"
	"fmt"
	"strings"

	indicatorclient "github.com/folio-sec/terraform-provider-microsoftdefender/internal/client/endpoint/indicator"
	providertypes "github.com/folio-sec/terraform-provider-microsoftdefender/internal/types"
	"github.com/folio-sec/terraform-provider-microsoftdefender/internal/validation"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
)

func (r *indicatorResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan resourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if matches, err := r.resolve(ctx, plan.IndicatorValue.ValueString(), ""); err == nil && len(matches) > 0 {
		resp.Diagnostics.AddError("Indicator already exists", fmt.Sprintf("An Indicator with value %q already exists. Import it instead of creating it.", plan.IndicatorValue.ValueString()))
		return
	} else if err != nil {
		resp.Diagnostics.AddError("Unable to check for an existing Indicator", err.Error())
		return
	}
	requested := apiIndicator(ctx, plan, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}
	created, err := r.client.Submit(ctx, requested)
	if err != nil {
		if !mutationOutcomeMayBeAmbiguous(err) {
			resp.Diagnostics.AddError("Unable to create Indicator", err.Error())
			return
		}
		matches, resolveErr := r.resolve(ctx, plan.IndicatorValue.ValueString(), "")
		if resolveErr != nil || len(matches) != 1 {
			resp.Diagnostics.AddError("Unable to verify Indicator creation", fmt.Sprintf("The POST outcome was ambiguous and exact-value verification failed. Original error: %s. The Indicator may exist and require import.", err))
			return
		}
		if mismatches := indicatorMismatches(matches[0], requested); len(mismatches) > 0 {
			resp.Diagnostics.AddError(
				"Unable to verify Indicator ownership",
				fmt.Sprintf("The POST outcome was ambiguous and the Indicator found by value differs from the request in: %s. Refusing to adopt it because it may have been created by another actor. Original error: %s.", strings.Join(mismatches, ", "), err),
			)
			return
		}
		created = matches[0]
	}
	if created.ID == "" {
		resp.Diagnostics.AddError("Invalid create response", "Microsoft Defender returned an Indicator without an ID.")
		return
	}
	setState(ctx, &plan, created, &resp.Diagnostics)
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *indicatorResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state resourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	matches, err := r.resolve(ctx, state.IndicatorValue.ValueString(), state.ID.ValueString())
	if err != nil {
		resp.Diagnostics.AddError("Unable to read Indicator", err.Error())
		return
	}
	if len(matches) == 0 {
		resp.State.RemoveResource(ctx)
		return
	}
	setState(ctx, &state, matches[0], &resp.Diagnostics)
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *indicatorResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan resourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	updated, err := r.client.Submit(ctx, apiIndicator(ctx, plan, &resp.Diagnostics))
	if resp.Diagnostics.HasError() {
		return
	}
	if err != nil {
		resp.Diagnostics.AddError("Unable to update Indicator", err.Error())
		return
	}
	if updated.ID == "" {
		updated.ID = plan.ID.ValueString()
	}
	if updated.ID != plan.ID.ValueString() {
		resp.Diagnostics.AddError("Unexpected Indicator update response", fmt.Sprintf("The API returned ID %q while updating ID %q.", updated.ID, plan.ID.ValueString()))
		return
	}
	setState(ctx, &plan, updated, &resp.Diagnostics)
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *indicatorResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state resourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if err := r.client.Delete(ctx, state.ID.ValueString()); err != nil {
		resp.Diagnostics.AddError("Unable to delete Indicator", err.Error())
	}
}

func (r *indicatorResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	value := strings.ToLower(req.ID)
	if !validation.IsHexHash(value, validation.SHA256HexLength) {
		resp.Diagnostics.AddError("Invalid Indicator import value", "Import currently accepts a FileSha256 indicator_value: exactly 64 hexadecimal characters.")
		return
	}
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("indicator_value"), providertypes.LowerStringValueOf(value))...)
}

func (r *indicatorResource) resolve(ctx context.Context, value, expectedID string) ([]indicatorclient.Indicator, error) {
	matches, err := r.client.FindByValue(ctx, value)
	if err != nil {
		return nil, fmt.Errorf("find Indicator by value: %w", err)
	}
	exact := make([]indicatorclient.Indicator, 0, len(matches))
	for _, candidate := range matches {
		if !indicatorValuesEqual(candidate.IndicatorValue, value) {
			continue
		}
		exact = append(exact, candidate)
	}
	if len(exact) > 1 {
		return nil, fmt.Errorf("indicatorValue filter returned %d exact matches; refusing to select one", len(exact))
	}
	if len(exact) == 1 && expectedID != "" && exact[0].ID != expectedID {
		return nil, fmt.Errorf("indicatorValue %q resolved to API ID %q, but Terraform manages ID %q; refusing to adopt or remove either Indicator", value, exact[0].ID, expectedID)
	}
	return exact, nil
}

func mutationOutcomeMayBeAmbiguous(err error) bool {
	var notSentErr *indicatorclient.RequestNotSentError
	if errors.As(err, &notSentErr) {
		return false
	}
	var httpErr *indicatorclient.HTTPError
	return !errors.As(err, &httpErr) || httpErr.StatusCode >= 500 && httpErr.StatusCode <= 599
}
