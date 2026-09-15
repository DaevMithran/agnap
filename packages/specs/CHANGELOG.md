# Changelog

All specification files share the version in `VERSION`.

## 0.1.0

First cut, milestone 1 surface only. `as.yaml` starts from Open Payments
`auth-server.yaml` 1.4.0 and departs from it as follows. Each item is a
deliberate widening or narrowing so the two remain comparable for interop
testing against Rafiki.

Widened:

- `agent_operation` authority can carry an AGNAP-specific absolute `validity`
  window with an inclusive `not_before` and exclusive `not_after`. This is
  distinct from GNAP's token-level `expires_in`. Delegated windows must be
  contained within their parent's window.
- `access` items accept the `agent_operation` type from `schema/authority.json`
  and a generic RFC 9635 access object, instead of the three fixed Open
  Payments types. String references are accepted as RFC 9635 allows.
- `access_token` in a grant request may be a single request or an array, as
  RFC 9635 section 2.1 allows. Open Payments accepts only the single form.
- `client.key.proof` accepts the RFC 9635 object form
  (`{"method": "httpsig", "alg": "ed25519", "content-digest-alg": "sha-256"}`)
  as well as the string form.
- `POST /introspect` (RFC 9767 section 3.3) is added. Open Payments does not
  implement introspection because its resource servers share a database with
  the authorization server.
- `manage` in an access token response is the RFC 9635 object
  (`{"uri": ..., "access_token": {"value": ...}}`), not the pre-RFC string.
- Grant request carries an optional `delegation` field and grant and
  introspection responses carry optional `delegation_ref`, `receipt` and
  `credential_refs` fields. These are AGNAP extensions and are marked as such.
  The milestone 1 server rejects `delegation` and never emits the others.

Narrowed:

- Only the `httpsig` proofing method and Ed25519 keys (`alg: EdDSA`) are
  accepted.
- GNAP's `bearer` and `durable` access-token flags are accepted as request
  syntax only so the server can return `invalid_flag`. The AGNAP profile never
  issues or introspects an agent-facing token as bearer; every such token is
  bound to the requesting client instance's key. Durable tokens are not issued
  either. This does not prohibit the vault from privately using a downstream
  bearer credential.
- The Open Payments wallet address forms of `client` are removed. `client` is
  the RFC 9635 instance identifier string or an object carrying `key`.
- Open Payments `limits`, `interval`, `cardAuthorization` and `subject`
  request shapes are removed. Quantitative limits are expressed as `ceilings`
  in `authority.json`.
- Continuation (`/continue/{id}`), token management (`/token/{id}`) and
  resource registration (`/resource`) are not in this version. They return in
  the version that implements interaction and delegation.

Cosmetic:

- Schema names are `PascalCase` (Open Payments uses `kebab-case`).
- Every body is a `$ref` into `components/schemas`.
