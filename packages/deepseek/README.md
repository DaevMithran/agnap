# `@agnap/deepseek`

DeepSeek Harness tool authorization backed by key-bound GNAP grants, with
protected tools performed by the AGNAP executor.

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
- the fixed tool profiles; and
- optionally, how long a call waits for the owner (`ownerWaitSeconds`, default
  300).

The AS resource-server registry must contain the matching public JWK with the
`agent_operation` access type. Session client keys and grants remain in memory
and are keyed by the Harness agent's `id`.

The plugin holds no owner credential and cannot approve a grant. When a call
needs a new grant, the plugin requests it, naming the agent in RFC 9635
`client.display` (for example `agent child (subagent of parent)`), and waits
for the server to issue or deny it. The owner decides in a separate process with
[`agnap-owner`](../owner/README.md), whose requests the server accepts only
when they are signed with the owner key. The Harness approval prompt is not
used, so delegated subagents, whose approval policy the Harness pins to
`never`, can also be granted access. If the owner does not decide within
`ownerWaitSeconds`, the call is denied. Once a grant is issued the plugin
delegates with `next()`, so it does not bypass later Harness policies.

The config accepts only a key-file path, never inline private material.
Production deployment still needs a key-provider adapter.

No operation profiles are built in. Profiles must be written against the exact
tool schemas in the pinned Harness deployment; unknown arguments fail closed.
Each mapped argument must also choose its authority role: `identity` binds the
grant to the observed value (for example, a repository), while `free` requests
a wildcard (for example, a pull-request title). The default is `identity`.
Calls outside an existing grant request a new grant and ask the owner again;
they are not hard-denied merely because another grant covers the same
operation.

## Through the executor

With `executorUrl` set, profiled tools are performed by
[`agnapd`](../executor/README.md) instead of their in-process bodies, which
never run. The plugin's `tools/execute` listener sends the mapped operation
to the executor, carrying the grant's token and signed with the session's
client key. The executor introspects the token, verifies the signature
against the bound key, checks the grant covers the call, counts it against
the grant state record, and calls the downstream API with a credential only
it holds. The result goes back to the model as the tool's value; a refusal
(`ceiling_reached`, `insufficient_access`, …) or a downstream failure becomes
the tool error.

In this mode the plugin holds no resource-server key: `resourceServerId` and
`resourceServerPrivateJwkFile` are not needed, and the plugin does not
introspect. A token the executor reports as inactive is dropped, so the next
call requests a new grant.

A profile may ask for a ceiling, recorded in the grant state record, which the owner sees on the grant card
and the executor enforces across tokens and parallel calls:

```yaml
- toolName: comment
  operation: github.comment.create
  arguments:
    repository: {}
    issue: {}
    body: { authority: free }
  ceiling: { calls: 3 }
```

## Without the executor

The plugin and the tool body then share one process. There is no
resource-request signature to verify at tool-use time: the AS binds
continuation and management operations to the client key, and RFC 9767
introspection returns the bound key, but the plugin does not prove possession
of that key for each in-process call. It introspects a stored grant before
reusing it, to notice revocation, and checks coverage itself. Ceilings are
not enforced in this mode.

## Lifecycle

Unprofiled tools delegate to later Harness policies by default. Set
`denyUnprofiledTools` to make the adapter deny them instead.

The high-level adapter listens for the pinned Harness `agent/disposed` event
and revokes the agent's live grants. Low-level hosts that omit
`disposedSessionId` should call `authorizer.disposeSession(id)` themselves;
otherwise token TTL is their cleanup bound.

On Harness shutdown the plugin is torn down before its agents, so
`agent/disposed` never reaches it. The plugin therefore also revokes every
session's grants when it unloads, waiting at most `unloadRevokeTimeoutMs`
(default 3000). A grant the server cannot be reached to revoke stays live until
its TTL.

Hosts that construct `GnapToolAuthorizer` themselves may still pass an `owner`
port, which collects the decision through the Harness approval prompt. That
path puts the owner's power in the agent's process and exists for tests; the
entry point never uses it.

## Run the local PoC with DeepSeek Harness

This walkthrough is verified against DeepSeek Harness `0.2.1-alpha.1` at commit
`5badb15009ae1756c3afe0ae0cef1faafc290ccc`. It uses three terminals: the
authorization server, the owner, and the Harness.

### 1. Build AGNAP and create keys

From the AGNAP checkout:

```sh
pnpm install
pnpm build
node packages/deepseek/examples/create-demo-keys.mjs /tmp/agnap-deepseek-demo
node packages/owner/dist/cli.js keygen ~/.config/agnap-owner
```

The first command writes the resource-server key and registry the plugin and
server share. The second writes the owner key pair; keep `owner.jwk` away from
the agent's user. Both refuse to overwrite existing files.

### 2. Start the authorization server

```sh
pnpm gnap-server serve \
  --port 4000 \
  --issuer http://127.0.0.1:4000/ \
  --rs-registry /tmp/agnap-deepseek-demo/deepseek-rs-registry.json \
  --owner-key ~/.config/agnap-owner/owner.pub.jwk \
  --continue-wait 1
```

The startup line should report `owner=owner-key`. `--continue-wait 1` makes
the plugin pick up the owner's decision within a second. Loopback HTTP and the
in-memory store are suitable only for this local demonstration.

### 3. Start the owner

```sh
node packages/owner/dist/cli.js watch --url http://127.0.0.1:4000/
```

Each pending grant appears as a card: the agent's name, each requested
operation with its arguments, and the time left. Answer `a` to approve, `n` to
keep only some operations, `d` to deny or `s` to skip.

### 4. Add the plugin to the Harness composition

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
        tokenTtlSeconds: 600
        ownerWaitSeconds: 300
        denyUnprofiledTools: false
        unloadRevokeTimeoutMs: 3000
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

### 5. Start DeepSeek Harness

From the pinned DeepSeek Harness checkout:

```sh
pnpm dsh web --patch /tmp/agnap-deepseek.overlay.yml
```

Ask the agent to execute a simple shell command, such as `pwd`. The tool call
waits while the owner terminal shows the grant.

### 6. Verify the behavior

- Approve the first `pwd` grant in the owner terminal: the plugin obtains a
  token on its next poll and the command runs.
- Repeat the same command before expiry: the active grant is introspected and
  the owner is not asked again.
- Request a different command: its exact `command` constraint requires a new
  grant, which appears in the owner terminal.
- Deny a grant: the tool call fails with "the owner denied the grant".
- Dispose the agent: the plugin attempts to revoke every live session grant.
- Stop the Harness: the plugin revokes the grants of every session.

`harness-e2e/` automates these checks against the pinned Harness with a
scripted owner; see its README.
