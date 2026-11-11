# Changelog

All specification files share the version in `VERSION`.

## Unreleased

- `local-owner.yaml`: requests may be authenticated by an RFC 9421 signature
  with the owner key (`ownerSignature`) as well as by the shared secret, which
  is now documented as tests-only.
- `local-owner.yaml`: `PendingGrant` gains optional `client_display`, the
  client's RFC 9635 `client.display`, unverified.
- `agent-operation.json`: optional `ceilings`, `{ <operation>: { calls } }`,
  checked by the executor against the grant state record of the root grant.
  A narrower item must keep a ceiling no larger than the wider item's.
- `as.yaml`: `IntrospectionResponse` gains optional `root_grant`, the grant a
  token's calls are recorded against in the grant state record.

## 0.2.0

`as.yaml` is replaced by the contract of the generic GNAP authorization
server profile implemented in `packages/gnap-server`. It is the single
editable copy; the server package carries no spec of its own and a test in
`gnap-server` checks that the routes it registers are exactly the paths and
methods declared here.

- Paths: `POST /`, `POST /continue/{id}`, `DELETE /token/{id}`,
  `POST /introspect`. Continuation and token management are new. Asynchronous
  authorization only: responses carry `continue` with `wait`, never `interact`.
- Token revocation presents the token management access token, distinct from
  the access token.
- Introspection follows RFC 9767 section 3.3 with a resource server registry,
  per-token audiences, `iss` required when active, and the `invalid_resource_server`
  and `invalid_access` error codes.
- Access items are `{ type, ... }` objects handled by a registered type;
  reference strings are refused. The AGNAP extension fields (`delegation`,
  `runtime_evidence`, `delegation_ref`, `root_ref`, `runtime_ref`, `receipt`)
  are gone from this contract.
- `local-owner.yaml` documents the non-RFC owner extension under `/local/grants`.
- OpenAPI component schemas are the source for generated TypeScript wire types
  and Ajv runtime validators. Zod is no longer a second schema definition.
- `schema/agent-operation.json` is the shipped exact/wildcard access vocabulary;
  `authority.json` remains the separate forward-looking policy model.
- The retired `vault.yaml` surface is no longer exported. The `schema/` files
  remain forward-looking design artifacts and are not implemented completely by
  the current packages.

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
- Grant request carries optional `delegation` and `runtime_evidence` fields.
  The milestone 1 server explicitly rejects both rather than claiming a
  lineage or runtime binding it did not verify.
- Grant and introspection responses carry stable `delegation_ref` and
  `root_ref` values. Runtime-bound implementations also return `runtime_ref`.
- `context.json` defines the server-side root authorization context, signed
  runtime evidence and credential ownership binding. External identity is an
  optional root-authorization input; local deployment policy can authorize a
  root without it. Every root and credential remains bound to an opaque
  security domain, and raw identity claims are not exposed to agents or vaults.
- A root authorization context carries an effective `delegation_policy` with
  an explicit `automatic` or `manual` mode. The owner or trusted organization
  policy sets it; an agent cannot set it authoritatively.
- Delegation is strictly attenuating. A child wider than its parent is always
  rejected. Newly approved additional authority starts a separate root
  lineage rather than appearing as a wider child.
- Introspection defines fail-closed active-state semantics for expiry, node or
  ancestor revocation, root revocation, stopped runtimes and withdrawn
  credential bindings.

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
