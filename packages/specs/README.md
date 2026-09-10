# @agnap/specs

The normative OpenAPI and JSON Schema artifacts for AGNAP. Nothing in this
package is executable code. Implementations can generate native types from
these files and use the same schemas to validate protocol traffic at runtime.

This follows the pattern of
[interledger/open-payments-specifications](https://github.com/interledger/open-payments-specifications),
the only GNAP authorization server specification in production use. See
`CHANGELOG.md` for each place where this specification widens or departs from
the Open Payments `auth-server.yaml`.

```text
openapi/
  as.yaml           Authorization Server grant and token introspection API
  vault.yaml        agent operation invocation API and error shapes
schema/
  authority.json    operations, constraints, validity windows and ceilings
  delegation.json   delegation assertion claims and AS-signed receipts
VERSION             one version for all files, bumped together
```

`authority.json` and `delegation.json` are written in JSON Schema 2020-12,
which OpenAPI 3.1 shares, so `as.yaml` references them instead of restating
them. They are also the appendix a future Internet-Draft will reference, and
what a port in another language validates against.

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
pnpm --filter @agnap/specs lint     # redocly lint
```

Changes must keep the OpenAPI documents and referenced JSON Schemas valid.
Implementations consuming the package are responsible for regenerating any
derived language types after a specification update.
