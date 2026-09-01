package types

import (
	"context"
	"fmt"
	"strings"

	"github.com/folio-sec/terraform-provider-microsoftdefender/internal/validation"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/types/basetypes"
	"github.com/hashicorp/terraform-plugin-go/tftypes"
)

type LowerStringType struct{ basetypes.StringType }

func (t LowerStringType) Equal(other attr.Type) bool {
	_, ok := other.(LowerStringType)
	return ok
}

func (t LowerStringType) String() string { return "LowerStringType" }

func (t LowerStringType) ValueFromString(_ context.Context, in basetypes.StringValue) (basetypes.StringValuable, diag.Diagnostics) {
	if !in.IsNull() && !in.IsUnknown() {
		in = basetypes.NewStringValue(normalizeHash(in.ValueString()))
	}
	return LowerStringValue{StringValue: in}, nil
}

func (t LowerStringType) ValueFromTerraform(ctx context.Context, in tftypes.Value) (attr.Value, error) {
	value, err := t.StringType.ValueFromTerraform(ctx, in)
	if err != nil {
		return nil, fmt.Errorf("convert Terraform string: %w", err)
	}
	stringValue, ok := value.(basetypes.StringValue)
	if !ok {
		return nil, fmt.Errorf("unexpected value type %T", value)
	}
	converted, diagnostics := t.ValueFromString(ctx, stringValue)
	if diagnostics.HasError() {
		return nil, fmt.Errorf("convert lowercase string: %v", diagnostics)
	}
	return converted, nil
}

func (t LowerStringType) ValueType(context.Context) attr.Value { return LowerStringValue{} }

type LowerStringValue struct{ basetypes.StringValue }

func (v LowerStringValue) Equal(other attr.Value) bool {
	otherValue, ok := other.(LowerStringValue)
	return ok && v.StringValue.Equal(otherValue.StringValue)
}

func (v LowerStringValue) Type(context.Context) attr.Type { return LowerStringType{} }

func (v LowerStringValue) StringSemanticEquals(ctx context.Context, other basetypes.StringValuable) (bool, diag.Diagnostics) {
	if v.IsNull() || v.IsUnknown() || other.IsNull() || other.IsUnknown() {
		return false, nil
	}
	otherValue, diagnostics := other.ToStringValue(ctx)
	left, right := v.ValueString(), otherValue.ValueString()
	if normalizeHash(left) != left || normalizeHash(right) != right {
		return strings.EqualFold(left, right), diagnostics
	}
	return left == right, diagnostics
}

func LowerStringValueOf(value string) LowerStringValue {
	return LowerStringValue{StringValue: basetypes.NewStringValue(normalizeHash(value))}
}

func normalizeHash(value string) string {
	if validation.IsSupportedHash(value) {
		return strings.ToLower(value)
	}
	return value
}
