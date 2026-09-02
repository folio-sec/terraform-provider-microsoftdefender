# Repository guidance

## Language and contributions

- Write repository artifacts in English.
- Sign off every commit for DCO compliance with `git commit --signoff`.
- Do not log credentials, bearer tokens, OIDC assertions, or client secrets.

## Architecture

- Keep the Microsoft Defender for Endpoint native API client under
  `internal/client/endpoint` and Terraform lifecycle code under
  `internal/services/endpoint`.
- Keep the API host and token scope separate. The native API uses
  `api.security.microsoft.com`, while tokens use the legacy
  `api.securitycenter.microsoft.com/.default` audience.
- Inject token credentials, HTTP clients, and base URLs so unit tests never
  require a live Microsoft Entra tenant.
- Use `github.com/hashicorp/go-retryablehttp` for transport retries. Retry only
  safe GET requests for 429, 500, 502, 503, and 504 responses. Bound both
  `Retry-After` waits and the total retry duration; never retry POST or DELETE
  automatically.
- Do not add Microsoft Graph Security Indicator API code.
- Do not retry mutations unless an operation has proven idempotency. Verify an
  ambiguous create outcome with a read when possible.
- Before implementing validation, parsing, escaping, authentication,
  cryptography, retry, or other security-sensitive behavior, check for an
  appropriate Go standard library package, official SDK, Terraform Plugin
  Framework feature, or actively maintained library and prefer it over custom
  code. When custom security-sensitive logic is unavoidable, document why no
  suitable library applies, strictly bound its inputs, and cover malformed and
  adversarial inputs with tests.

## Terraform and generated files

- Preserve native API vocabulary in resource schemas.
- Keep string import compatibility. Add resource identity only when its value
  exceeds the implementation and maintenance cost.
- Keep each resource example limited to the documented resource block.
- Run `make generate/docs` after schema, template, or example changes.
- Before handoff run `make build`, `make lint`, `go test -race ./...`, and
  `git diff --check`.
- Pin third-party GitHub Actions to full commit SHAs.
