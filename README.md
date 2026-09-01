# Terraform Provider Microsoft Defender

Terraform provider for managing Microsoft Defender for Endpoint configuration
through the Defender for Endpoint native API.

## Documentation

See the generated [provider documentation](docs/index.md) and
[`microsoftdefender_indicator` resource documentation](docs/resources/indicator.md).
Microsoft also publishes documentation for the
[Defender for Endpoint Indicator API](https://learn.microsoft.com/en-us/defender-endpoint/api/ti-indicator).

## Requirements

- [Terraform](https://developer.hashicorp.com/terraform/downloads)
- [Go](https://go.dev/doc/install)

## Building the Provider

1. Clone the repository.
2. Enter the repository directory.
3. Build the provider:

```sh
make build
```

The provider binary is written to `bin/terraform-provider-microsoftdefender`.

## Using the Provider

Declare the provider source and configure credentials through environment
variables:

```hcl
terraform {
  required_providers {
    microsoftdefender = {
      source = "folio-sec/microsoftdefender"
    }
  }
}

provider "microsoftdefender" {}
```

### Authentication

For client credential authentication, configure the following variables. Do
not put the client secret directly in Terraform configuration.

```sh
export MICROSOFTDEFENDER_TENANT_ID="00000000-0000-0000-0000-000000000000"
export MICROSOFTDEFENDER_CLIENT_ID="00000000-0000-0000-0000-000000000000"
export MICROSOFTDEFENDER_CLIENT_SECRET="..."
```

OIDC workload identity federation is also supported through an assertion or
token file. GitHub Actions is detected automatically from
`ACTIONS_ID_TOKEN_REQUEST_URL` and `ACTIONS_ID_TOKEN_REQUEST_TOKEN` when the
job has `id-token: write`. See the
[provider documentation](docs/index.md) for all supported variables.

The provider calls `https://api.security.microsoft.com`. Access tokens use the
distinct `https://api.securitycenter.microsoft.com/.default` scope, not a
Microsoft Graph scope.

## Developing the Provider

Run the local checks and regenerate documentation with:

```sh
make test
make lint
make vulncheck
make generate
git diff --check
```

Unit tests use injected credentials and HTTP transports and do not require a
live Microsoft Entra tenant.

`make testacc` runs the live acceptance test only when `TF_ACC=1` and one
supported authentication source is configured. It creates, updates, imports,
and deletes a random, two-hour-expiring Indicator in the target tenant.

## Debugging the Provider

Start the provider in Terraform Plugin Framework debug mode:

```sh
go run . -debug
```

Use the emitted `TF_REATTACH_PROVIDERS` value when running Terraform from
another terminal. Never enable verbose logging with real credentials in shared
or public environments.

## Release

The repository uses [tagpr](https://github.com/Songmu/tagpr) for version pull
requests and [GoReleaser](https://goreleaser.com/) for signed Terraform Registry
release artifacts.

## Contribution

See [CONTRIBUTING.md](CONTRIBUTING.md). Every commit must include a DCO
sign-off.
