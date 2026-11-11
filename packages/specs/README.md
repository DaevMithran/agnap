# @agnap/specs

The shipped OpenAPI contracts and forward-looking JSON Schema artifacts for
AGNAP. Nothing in this package is executable code. Implementations can generate
native types from the current contracts; planned schemas are design inputs until
an implementation adopts them.

This follows the pattern of
[interledger/open-payments-specifications](https://github.com/interledger/open-payments-specifications),
the only GNAP authorization server specification in production use. See
`CHANGELOG.md` for each place where this specification widens or departs from
the Open Payments `auth-server.yaml`.

```text
openapi/
  as.yaml           GNAP authorization server profile: grant, continue, revoke, introspect
  local-owner.yaml  the non-RFC local owner extension, /local/grants
schema/
  agent-operation.json  shipped agent_operation access type
  authority.json    planned operations, constraints, validity windows and ceilings
  context.json      planned approval, runtime evidence and credential binding
  delegation.json   planned delegation assertions and AS-signed receipts
VERSION             one version for all files, bumped together
```

`as.yaml`, `local-owner.yaml`, and `schema/agent-operation.json` describe the
currently shipped surface. The other files under `schema/` are forward-looking design artifacts for delegation,
runtime evidence, credential binding, validity windows, and conserved ceilings;
the current packages do not implement those complete schemas. They are kept as
JSON Schema 2020-12 candidates for a future Internet-Draft and should not be
read as claims about shipped behavior.

The retired vault OpenAPI document moved to the ignored local archive with its
implementation. A future execution-service API should be designed from the
current resource-server boundary rather than reviving that document.

## Conventions

- Schema names are `PascalCase`. Wire field names follow the RFCs (`snake_case`).
- Every request and response body is a `$ref` into `components/schemas`.
- Objects are closed (`additionalProperties: false`) unless the description
  names them as an extension point. The two extension points today are the
  generic RFC 9635 access object and connector operation arguments.
- Extension fields that are not in RFC 9635 or RFC 9767 carry the phrase
  `AGNAP extension` in their description.

## Working on the specification

```sh
pnpm --filter @agnap/specs generate # regenerate TypeScript types and runtime schema bundles
pnpm --filter @agnap/specs lint     # redocly lint
```

Generated TypeScript types and Ajv schema bundles live in the packages that
consume them. The lint command fails when those artifacts are stale. Tests
compile all published JSON Schemas together under JSON Schema 2020-12 and
validate exercised handler responses against the generated validators.
