# `@agnap/executor` (`agnapd`)

The executor is the resource server that actually performs agent operations.
It holds the downstream credentials, so the agent never does. For each call
it:

1. reads the GNAP token and introspects it at the grant server (RFC 9767);
2. verifies the request signature against the key the token is bound to
   (RFC 9421, with a nonce replay check);
3. checks that the grant covers the operation and its arguments
   (`agent_operation`, closed world: an argument the grant does not name is
   refused);
4. if the grant ceilings the operation, reserves one call on the grant state
   record and refuses the call when the record is full;
5. calls the downstream service through the operation's connector, then
   settles the reservation.

```
agent ──signed POST /operations/{op}──▶ agnapd ──introspect──▶ grant server
                                           │
                                           ├─ grant state record (root grant, op)
                                           └─ connector + credential ──▶ API
```

## Calling an operation

```http
POST /operations/github.comment.create
Authorization: GNAP <access token>
Content-Type: application/json
Content-Digest: sha-256=:…:
Signature-Input: sig=("@method" "@target-uri" "authorization" "content-digest");…
Signature: sig=:…:

{ "arguments": { "repository": "acme/docs", "issue": 12, "body": "Looks good" } }
```

Arguments are scalars (string, number, boolean). Responses:

| Status | `error.code`           | Meaning                                                                          |
| ------ | ---------------------- | -------------------------------------------------------------------------------- |
| 200    |                        | `{ "result": … }` from the connector                                             |
| 400    | `invalid_request`      | body is not `{ "arguments": { … scalars } }`                                     |
| 401    | `invalid_token`        | missing, unknown, expired or revoked token                                       |
| 401    | `invalid_signature`    | not signed by the token's key, or a replayed request                             |
| 403    | `insufficient_access`  | the grant does not cover this operation with these arguments                     |
| 403    | `ceiling_reached`      | the grant state record is at the grant's ceiling (`ceiling`, `counted` included) |
| 404    | `unknown_operation`    | no connector serves this operation                                               |
| 502    | `operation_failed`     | the downstream call failed; `effect` is `none` or `unknown`                      |
| 503    | `introspection_failed` | the grant server could not be reached                                            |

Nothing reaches the downstream service unless every check passed.

## Grant state record

The grant state record is the shared state of a grant, kept by the executor
outside every token. It holds, per root grant and operation, how many calls
were used, are in flight, or have an unknown outcome. A grant sets the ceiling
the record is checked against:

```json
{
  "type": "agent_operation",
  "operations": {
    "github.comment.create": {
      "repository": { "exact": "acme/docs" },
      "body": { "wildcard": true }
    }
  },
  "ceilings": { "github.comment.create": { "calls": 3 } }
}
```

Every token of the root grant, and (later) every child grant derived from it,
counts against the same record, so the ceiling holds across tokens, agents and
parallel calls. Each call is reserved on the record before the connector runs
and settled after:

| Outcome                                   | Settlement | Counted? |
| ----------------------------------------- | ---------- | -------- |
| connector succeeded                       | `used`     | yes      |
| refused downstream, nothing happened      | `released` | no       |
| failed with unknown effect (5xx, timeout) | `held`     | yes      |

A held call stays counted: the ceiling errs towards fewer effects, never more.
The owner can grant again if a held call really did nothing.

A narrower grant must keep the ceiling: containment checks that a narrower
item has a ceiling no larger than the wider one's.

## Pluggable parts

`createExecutor` takes three interfaces (see `src/types.ts`):

- **`Connector`** performs operations against one downstream service. The
  built-in `HttpConnector` maps each operation to a method and a path
  template (`{name}` is percent-encoded, `{+name}` is kept as is), with named
  arguments in the query or a JSON body. A failure reports `effect: 'none'`
  or `'unknown'`; a thrown error counts as unknown.
- **`GrantStateStore`** is the grant state record: `reserve`, `settle`,
  `snapshot`. `reserve` must be atomic across every process that shares the
  store. `MemoryGrantStateStore` is for one process; `SqliteGrantStateStore` uses
  `BEGIN IMMEDIATE` transactions, so several `agnapd` processes can share one
  database file.
- **`Introspector`** looks tokens up. `GnapIntrospector` signs the request
  with the executor's resource-server key.

```ts
import { createExecutor, GnapIntrospector, SqliteGrantStateStore } from '@agnap/executor';

const handler = createExecutor({
  introspector: new GnapIntrospector({ issuer, resourceServerId: 'agnapd', signer }),
  connectors: [myConnector],
  grantState: new SqliteGrantStateStore('grant-state.db'),
  log: (event) => console.log(event), // never contains tokens or credentials
});
// handler: (Request) => Promise<Response>
```

Connector types for the config file are registered by name
(`defaultConnectorFactories`; pass more to `startExecutor`), so a UTCP or MCP
connector can be added without touching the request path.

## Running it

Requires Node 22.13 or later (`node:sqlite`).

```sh
pnpm agnapd keygen agnapd-rs.jwk > rs-entry.json   # add the entry to the grant server's rs.json
pnpm gnap-server serve --rs-registry rs.json --owner-key ~/.agnap/owner.pub.jwk
CANARY_TOKEN=secret pnpm agnapd serve --config packages/executor/examples/agnapd.json
node packages/executor/examples/canary.mjs        # a stand-in API that logs what it receives
```

`examples/agnapd.json` shows the config. Credentials come from an
environment variable (`env`) or a file (`file`) and are read at call time;
the config itself cannot contain a secret. Relative paths resolve against the
config file's directory. Each decision is logged as one JSON line.

## Known limitations and future work

**Credential sources are fixed.** A connector reads its credential through
`credential.value(request)` on every call, after the call has been checked
against its grant; `request` names the operation and the root grant. The
config file accepts only `env` and `file`. The
executor holds every downstream credential, so it is the highest-value target
in a deployment. Planned:

- a `CredentialSource` interface with a registry, like connector factories;
- backends that keep credentials encrypted at rest: envelope encryption with
  the key-encryption key in AWS KMS, or in OpenBao/Vault Transit;
- a source that passes `request` to a separate broker, so each decrypt is
  approved only for a live, signed call that a grant covers.

This follows the token-vault designs in Christian Posta's credential
injection series on the agentgateway blog
(<https://agentgateway.dev/blog/2026-08-03-protecting-token-vault-kms-credential-injection/>,
<https://agentgateway.dev/blog/2026-11-02-protecting-token-vault-openbao-credential-injection/>).

**Downstream ceilings as a backstop.** Where a service can enforce a ceiling
itself (an Open Payments grant with `debitAmount`, a virtual card), a
connector should request one downstream credential per root grant carrying
the grant's ceiling, so the ceiling holds even if the executor is
compromised. The grant state record stays the source of truth across
services and subagents.
