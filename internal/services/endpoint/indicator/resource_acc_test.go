package indicator_test

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"testing"
	"time"

	providerimpl "github.com/folio-sec/terraform-provider-microsoftdefender/internal/provider"
	"github.com/hashicorp/terraform-plugin-framework/providerserver"
	"github.com/hashicorp/terraform-plugin-go/tfprotov6"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

func TestAccIndicatorFileSha256Allowed(t *testing.T) {
	if os.Getenv("TF_ACC") != "1" {
		t.Skip("set TF_ACC=1 to run acceptance tests")
	}
	requireAcceptanceAuthentication(t)

	var randomBytes [32]byte
	if _, err := rand.Read(randomBytes[:]); err != nil {
		t.Fatalf("generate acceptance-test Indicator value: %v", err)
	}
	indicatorValue := hex.EncodeToString(randomBytes[:])
	expirationTime := time.Now().UTC().Add(2 * time.Hour).Truncate(time.Second).Format(time.RFC3339)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: map[string]func() (tfprotov6.ProviderServer, error){
			"microsoftdefender": providerserver.NewProtocol6WithError(providerimpl.New("test")()),
		},
		Steps: []resource.TestStep{
			{
				Config: acceptanceIndicatorConfig(indicatorValue, expirationTime, "Acceptance test Indicator", "Created by the Terraform provider acceptance test"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("microsoftdefender_indicator.test", "id"),
					resource.TestCheckResourceAttr("microsoftdefender_indicator.test", "indicator_value", indicatorValue),
					resource.TestCheckResourceAttr("microsoftdefender_indicator.test", "indicator_type", "FileSha256"),
					resource.TestCheckResourceAttr("microsoftdefender_indicator.test", "action", "Allowed"),
				),
			},
			{
				Config: acceptanceIndicatorConfig(indicatorValue, expirationTime, "Updated acceptance test Indicator", "Updated by the Terraform provider acceptance test"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("microsoftdefender_indicator.test", "title", "Updated acceptance test Indicator"),
					resource.TestCheckResourceAttr("microsoftdefender_indicator.test", "description", "Updated by the Terraform provider acceptance test"),
				),
			},
			{
				ResourceName:      "microsoftdefender_indicator.test",
				ImportState:       true,
				ImportStateId:     indicatorValue,
				ImportStateVerify: true,
			},
		},
	})
}

func requireAcceptanceAuthentication(t *testing.T) {
	t.Helper()
	if firstEnvironment("MICROSOFTDEFENDER_TENANT_ID", "AZURE_TENANT_ID") == "" {
		t.Skip("acceptance tests require MICROSOFTDEFENDER_TENANT_ID or AZURE_TENANT_ID")
	}
	if firstEnvironment("MICROSOFTDEFENDER_CLIENT_ID", "AZURE_CLIENT_ID") == "" {
		t.Skip("acceptance tests require MICROSOFTDEFENDER_CLIENT_ID or AZURE_CLIENT_ID")
	}
	authenticationSources := 0
	for _, value := range []string{
		os.Getenv("MICROSOFTDEFENDER_CLIENT_SECRET"),
		os.Getenv("MICROSOFTDEFENDER_OIDC_TOKEN"),
		firstEnvironment("MICROSOFTDEFENDER_OIDC_TOKEN_FILE_PATH", "AZURE_FEDERATED_TOKEN_FILE"),
	} {
		if value != "" {
			authenticationSources++
		}
	}
	if authenticationSources == 0 && os.Getenv("ACTIONS_ID_TOKEN_REQUEST_URL") != "" && os.Getenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN") != "" {
		authenticationSources++
	}
	if authenticationSources == 0 {
		t.Skip("acceptance tests require one client credential or OIDC authentication source")
	}
	if authenticationSources > 1 {
		t.Fatal("acceptance tests require exactly one client credential or OIDC authentication source")
	}
}

func firstEnvironment(names ...string) string {
	for _, name := range names {
		if value := os.Getenv(name); value != "" {
			return value
		}
	}
	return ""
}

func acceptanceIndicatorConfig(indicatorValue, expirationTime, title, description string) string {
	return fmt.Sprintf(`
provider "microsoftdefender" {}

resource "microsoftdefender_indicator" "test" {
  indicator_value = %q
  indicator_type  = "FileSha256"
  action          = "Allowed"
  title           = %q
  description     = %q
  expiration_time = %q

  severity         = "Informational"
  generate_alert   = false
  rbac_group_names = []
}
`, indicatorValue, title, description, expirationTime)
}
