# Contributing to AGNAP

AGNAP is currently publishing protocol specifications, schemas, and
explanatory documentation. Contributions should improve the clarity,
interoperability, security, or implementability of those artifacts.

By participating, you agree to follow the [Code of Conduct](CODE_OF_CONDUCT.md).
Report vulnerabilities through the private process in
[SECURITY.md](SECURITY.md), not through a public issue.

## Before opening a pull request

For a material protocol change, open an issue first. Describe the use case,
security consequences, compatibility impact, and alternatives. Editorial
corrections can go directly to a pull request.

Good contributions at this stage include:

- Clarifying ambiguous or inconsistent requirements.
- Improving OpenAPI or JSON Schema definitions.
- Adding examples, test vectors, or threat cases.
- Reviewing GNAP and HTTP Message Signature alignment.
- Identifying interoperability or implementation risks.

Implementation packages and runtime adapters are on the roadmap but are not
part of the published repository yet.

## Working with the specifications

The normative artifacts are under `packages/specs`:

- `openapi/as.yaml` defines the Authorization Server API.
- `openapi/vault.yaml` defines the vault invocation API.
- `schema/authority.json` defines agent authority.
- `schema/delegation.json` defines delegation assertions and receipts.

Install and lint the specification package:

```sh
pnpm --dir packages/specs install
pnpm --dir packages/specs lint
```

## Specification rules

- Treat OpenAPI and JSON Schema as the source of truth.
- Keep objects closed unless a field is an explicit extension point.
- Mark non-GNAP fields as an `AGNAP extension` in their descriptions.
- Use RFC 2119 requirement words deliberately and consistently.
- Include concrete valid and invalid examples for behavioral changes.
- Update `packages/specs/CHANGELOG.md` for a wire-level change.
- Update `packages/specs/VERSION` when preparing a release, not for every pull
  request.
- Explain compatibility and migration effects when changing an existing shape.

JSON Schema cannot express every semantic invariant. State such requirements
in descriptions and include proposed conformance cases where appropriate.

## Pull requests

Keep each pull request focused on one concern. Complete the pull request
template, link the relevant issue, and ensure the specification lint passes.
Reviews consider protocol correctness, security, compatibility, naming,
examples, and whether an independent implementation could reach the same
interpretation.

By submitting a contribution, you agree that it may be distributed under the
repository's [Apache License 2.0](LICENSE).
