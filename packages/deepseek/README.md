# `@agnap/deepseek`

DeepSeek Harness `tools/pre-execute` authorization backed by key-bound GNAP
grants.

This package is the DeepSeek Harness adapter. Generic GNAP messages, signing,
access-type registration, grant lifecycle, and owner-side narrowing belong to
[`@agnap/gnap-core`](../gnap-core/README.md),
[`@agnap/gnap-server`](../gnap-server/README.md), and
[`@agnap/access-types`](../access-types/README.md).

The package contains:

- strict tool-profile and argument mapping;
- one in-memory Ed25519 client key and token per Harness session;
- a distinct resource-server signer for RFC 9767 introspection;
- signed grant, continuation, introspection, and revocation requests;
- a fail-closed authorizer; and
- a structural adapter for DeepSeek Harness `0.2.1-alpha.1` at commit
  `5badb15009ae1756c3afe0ae0cef1faafc290ccc`.

It does not embed the authorization server. The server remains a configured URL,
so the same plugin can use a local sidecar or remote authorization server.

The package exports conventional Cordis `name` and `apply(ctx, config)` entry
points. The local PoC configuration contains:

- the GNAP issuer URL;
- the registered resource-server id and a path to its Ed25519 private JWK;
- the name of the environment variable holding the local-owner secret; and
- the fixed tool profiles.

The AS resource-server registry must contain the matching public JWK with the
`agent_operation` access type. Session client keys and grants remain in memory
and are keyed by the Harness agent's `id`.

The development-only `LocalOwnerClient` lets the Harness approval prompt drive
the local owner extension. It deliberately puts an owner secret in the plugin
process and must not be used as a production interaction mechanism.

The high-level config accepts only a key-file path and environment-variable
name, never inline private material. Both remain development-only. Production
deployment needs a key-provider adapter and a real GNAP interaction mode.

Unlike a normal `{ kind: 'ask' }` policy, the adapter calls the Harness approval
service inside its listener. This is necessary because the plugin must approve
the pending GNAP grant and finish continuation before it permits the first tool
execution. Once GNAP authorization succeeds it delegates with `next()`, so it
does not bypass later Harness policies.

No operation profiles are built in. Profiles must be written against the exact
tool schemas in the pinned Harness deployment; unknown arguments fail closed.
Each mapped argument must also choose its authority role: `identity` binds the
grant to the observed value (for example, a repository), while `free` requests
a wildcard (for example, a pull-request title). The default is `identity`.
Calls outside an existing grant request a new grant and prompt again; they are
not hard-denied merely because another grant covers the same operation.

The development owner bridge is intentionally approve/reject only. The prompt
shows both the mapped GNAP scope (`repository = "acme/app", title = any`) and
the concrete call, but it does not provide controls for narrowing that scope.
The server's owner API supports narrowing; a production interaction UI must
expose that capability before claiming the user shaped the scope.

The plugin and protected tool dispatcher currently share one process. There is
therefore no resource-request signature to verify at tool-use time. The AS
binds continuation and management operations to the client key, and RFC 9767
introspection returns the bound key, but this demo does not prove possession of
that key for each in-process tool call. It sends the current call's access in
the introspection request so the AS evaluates the requested-access rule.

Unprofiled tools delegate to later Harness policies by default. Set
`denyUnprofiledTools` to make the adapter deny them instead.

The high-level adapter listens for the pinned Harness `agent/disposed` event
and revokes the agent's live grants. Low-level hosts that omit
`disposedSessionId` should call `authorizer.disposeSession(id)` themselves;
otherwise token TTL is their cleanup bound.

## Run the local PoC with DeepSeek Harness

This walkthrough uses the Harness browser approval channel and the
development-only local-owner bridge. It is verified against DeepSeek Harness
`0.2.1-alpha.1` at commit `5badb15009ae1756c3afe0ae0cef1faafc290ccc`.
The authorization server and Harness may run in separate terminals, but both
must receive the same `GNAP_OWNER_SECRET` value.

### 1. Build AGNAP and create demo credentials

From the AGNAP checkout:

```sh
pnpm install
pnpm build
node packages/deepseek/examples/create-demo-keys.mjs /tmp/agnap-deepseek-demo
```

The helper refuses to overwrite existing files. Choose a new empty directory
when repeating the setup. The private JWK and owner secret are development
credentials; do not commit or reuse them.

### 2. Start the authorization server

In the AGNAP checkout:

```sh
export GNAP_OWNER_SECRET="$(tr -d '\n' < /tmp/agnap-deepseek-demo/owner-secret)"
pnpm gnap-server serve \
  --port 4000 \
  --issuer http://127.0.0.1:4000/ \
  --rs-registry /tmp/agnap-deepseek-demo/deepseek-rs-registry.json
```

The startup line should report `owner-extension=on`. Loopback HTTP and the
in-memory store are suitable only for this local demonstration.

### 3. Add the plugin to the Harness composition

Create `/tmp/agnap-deepseek.overlay.yml`. Replace `/absolute/path/to/agnap`
with the AGNAP checkout's absolute path:

```yaml
- insert:
    - id: agnap-deepseek
      name: /absolute/path/to/agnap/packages/deepseek/dist/index.js
      config:
        issuer: http://127.0.0.1:4000/
        resourceServerId: deepseek-harness
        resourceServerPrivateJwkFile: /tmp/agnap-deepseek-demo/deepseek-rs-private.jwk
        simulateOwnerSecretEnv: GNAP_OWNER_SECRET
        tokenTtlSeconds: 600
        denyUnprofiledTools: false
        profiles:
          - toolName: bash
            operation: shell.exec
            rejectUnknownArguments: true
            arguments:
              description:
                authority: free
              command:
                authority: identity
              timeoutMs:
                required: false
              workdir:
                required: false
              run_in_background:
                required: false
              sandbox_permissions:
                required: false
              justification:
                required: false
                authority: free
```

This profile binds the grant to the exact shell command while allowing the
human-readable description and justification to vary. Optional execution
controls become exact constraints when supplied. Tools without a profile still
flow to later Harness policies because `denyUnprofiledTools` is false.

### 4. Start DeepSeek Harness

From the pinned DeepSeek Harness checkout, export the same owner secret and
start the Web profile with the overlay:

```sh
export GNAP_OWNER_SECRET="$(tr -d '\n' < /tmp/agnap-deepseek-demo/owner-secret)"
pnpm dsh web --patch /tmp/agnap-deepseek.overlay.yml
```

Use the Harness normally and ask the agent to execute a simple shell command,
such as `pwd`. Before execution, the Harness approval panel should show the
GNAP operation, constrained arguments, concrete call, and token lifetime.

### 5. Verify the behavior

- Approve the first `pwd` call: the plugin resolves the pending grant, obtains
  a token through continuation, and then delegates to later Harness policies.
- Repeat the same command before expiry: the active grant is introspected and
  the GNAP prompt is not repeated.
- Request a different command: its exact `command` constraint requires a new
  grant and prompt.
- Reject a request: the tool call is denied and no token is stored.
- Dispose the agent: the plugin attempts to revoke every live session grant.

Harness approval is the interaction channel in this mode. AGNAP does not need
separate Slack or email configuration; any Harness answerer for
`approval/request` can carry the same request. The pinned checkout includes the
browser and ACP answerers, but no Slack or email answerer.
