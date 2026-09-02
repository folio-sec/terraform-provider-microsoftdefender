package main

import (
	"context"
	"flag"
	"log"

	"github.com/folio-sec/terraform-provider-microsoftdefender/internal/provider"
	"github.com/hashicorp/terraform-plugin-framework/providerserver"
)

var version = "dev"

func main() {
	var debug bool
	flag.BoolVar(&debug, "debug", false, "run the provider with debugger support")
	flag.Parse()

	err := providerserver.Serve(context.Background(), provider.New(version), providerserver.ServeOpts{
		Address: "registry.terraform.io/folio-sec/microsoftdefender",
		Debug:   debug,
	})
	if err != nil {
		log.Fatal(err)
	}
}
