package types

import frameworktypes "github.com/hashicorp/terraform-plugin-framework/types"

type StringValuable interface {
	IsNull() bool
	IsUnknown() bool
	ValueString() string
}

// StringPointer converts a known Terraform string to a pointer. Null and
// unknown values are represented by nil.
func StringPointer(value StringValuable) *string {
	if value.IsNull() || value.IsUnknown() {
		return nil
	}
	result := value.ValueString()
	return &result
}

// StringValue converts an optional string pointer to a Terraform string.
func StringValue(value *string) frameworktypes.String {
	if value == nil {
		return frameworktypes.StringNull()
	}
	return frameworktypes.StringValue(*value)
}
