package types

import (
	"testing"

	frameworktypes "github.com/hashicorp/terraform-plugin-framework/types"
)

func TestStringPointer(t *testing.T) {
	t.Parallel()
	if StringPointer(frameworktypes.StringNull()) != nil {
		t.Fatal("null string did not convert to nil")
	}
	if StringPointer(frameworktypes.StringUnknown()) != nil {
		t.Fatal("unknown string did not convert to nil")
	}
	if got := StringPointer(frameworktypes.StringValue("value")); got == nil || *got != "value" {
		t.Fatalf("known string converted to %#v", got)
	}
}

func TestStringValue(t *testing.T) {
	t.Parallel()
	if got := StringValue(nil); !got.IsNull() {
		t.Fatalf("nil converted to %s", got)
	}
	value := "value"
	if got := StringValue(&value); got.IsNull() || got.IsUnknown() || got.ValueString() != value {
		t.Fatalf("pointer converted to %s", got)
	}
}
