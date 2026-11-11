# `@agnap/owner`

`agnap-owner` is the resource owner's command-line tool. It lists the grants
agents are waiting on and approves, narrows or denies them. Every request it
sends is signed with the owner key, so the server can tell the owner from an
agent, and the agent never holds anything that can approve.

Run it as a user, or on a machine, the agent cannot reach.

## Set up

```sh
agnap-owner keygen                      # writes ~/.config/agnap-owner/owner.jwk and owner.pub.jwk
gnap-server serve --owner-key ~/.config/agnap-owner/owner.pub.jwk ...
```

`owner.jwk` is written with mode 0600 and is never overwritten. The server
accepts owner requests only when they are signed with the matching private
key, with the same replay check it applies to agents.

`--url` defaults to `$AGNAP_URL`, else `http://127.0.0.1:4000/`. `--key`
defaults to `$AGNAP_OWNER_KEY`, else `~/.config/agnap-owner/owner.jwk`.

## Decide interactively

```sh
agnap-owner watch
```

```text
Grant    8DtNXpCd7VZGdhaY
Agent    agent child (subagent of parent)   [name stated by the agent, unverified]
Key      agent  jdXoLB77kjKn…
Asks     1. github.issues.list  repository = "acme/docs", state = any
         2. github.comment.create  repository = "acme/docs"
Expires  in 9m 59s if undecided
[a]pprove  [n]arrow  [d]eny  [s]kip >
```

Every line of scope comes from the grant request itself. The agent's name is
what the agent sent as RFC 9635 `client.display` and is labelled as unverified.
`n` approves only the operations you list by number; the server rejects any
approval wider than the request. A skipped grant stays pending until it expires
or another decision is made. When input ends, `watch` stops.

One-off commands work the same way:

```sh
agnap-owner list
agnap-owner approve <grant-id> [--keep 1,3]
agnap-owner deny <grant-id>
```

## Decide by rules

For tests and benchmarks, `watch --rules rules.json` decides without a person:

```json
{
  "rules": [
    { "operation": "github.issues.*", "decision": "approve" },
    { "operation": "github.comment.create", "client": "agent child*", "decision": "deny" }
  ],
  "default": "deny"
}
```

Each requested operation takes the decision of the first rule whose
`operation` pattern (and `client` pattern, when given) matches. A grant is
approved only when every operation is approved; any denied operation denies it;
otherwise `default` applies (`approve`, `deny` or `skip`). A pattern is an exact
name, `*`, or a prefix ending in `*`. `--once` decides the grants pending now and
exits.

## Library

The package also exports `OwnerClient`, `watch`, `rulesDecider`,
`interactiveDecider`, `renderGrant` and `keepOperations`, so tests can run a
scripted owner in-process. `packages/deepseek/harness-e2e` does this.
