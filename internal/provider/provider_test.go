package provider

import (
	"context"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/provider"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

func TestMetadataSchemaAndResources(t *testing.T) {
	t.Parallel()
	subject := New("test")()
	var metadata provider.MetadataResponse
	subject.Metadata(context.Background(), provider.MetadataRequest{}, &metadata)
	if metadata.TypeName != "microsoftdefender" || metadata.Version != "test" {
		t.Fatalf("metadata = %#v", metadata)
	}
	var schemaResponse provider.SchemaResponse
	subject.Schema(context.Background(), provider.SchemaRequest{}, &schemaResponse)
	if len(schemaResponse.Schema.Attributes) != 5 || !schemaResponse.Schema.Attributes["client_secret"].IsSensitive() || !schemaResponse.Schema.Attributes["oidc_token"].IsSensitive() {
		t.Fatalf("schema attributes = %#v", schemaResponse.Schema.Attributes)
	}
	resources := subject.Resources(context.Background())
	if len(resources) != 1 {
		t.Fatalf("resources = %d", len(resources))
	}
	var resourceMetadata resource.MetadataResponse
	resources[0]().Metadata(context.Background(), resource.MetadataRequest{ProviderTypeName: "microsoftdefender"}, &resourceMetadata)
	if resourceMetadata.TypeName != "microsoftdefender_indicator" {
		t.Fatalf("resource type = %q", resourceMetadata.TypeName)
	}
}

func TestConfigurationValuePrecedence(t *testing.T) {
	t.Setenv("MICROSOFTDEFENDER_TEST_PRIMARY", "primary")
	t.Setenv("MICROSOFTDEFENDER_TEST_FALLBACK", "fallback")

	if got := configuredValue(types.StringValue("provider"), "MICROSOFTDEFENDER_TEST_PRIMARY"); got != "provider" {
		t.Fatalf("provider argument precedence = %q", got)
	}
	if got := configuredValue(types.StringNull(), "MICROSOFTDEFENDER_TEST_PRIMARY"); got != "primary" {
		t.Fatalf("environment fallback = %q", got)
	}
	if got := configuredValueWithFallback(types.StringNull(), "MICROSOFTDEFENDER_TEST_PRIMARY", "MICROSOFTDEFENDER_TEST_FALLBACK"); got != "primary" {
		t.Fatalf("environment priority = %q", got)
	}
	if got := configuredValue(types.StringValue(""), "MICROSOFTDEFENDER_TEST_PRIMARY"); got != "" {
		t.Fatalf("explicit empty provider argument = %q", got)
	}

	t.Setenv("MICROSOFTDEFENDER_TEST_PRIMARY", "")
	if got := configuredValueWithFallback(types.StringNull(), "MICROSOFTDEFENDER_TEST_PRIMARY", "MICROSOFTDEFENDER_TEST_FALLBACK"); got != "fallback" {
		t.Fatalf("secondary environment fallback = %q", got)
	}
}
