# Harness end-to-end test

`agnap-integration.spec.ts` runs `@agnap/deepseek` inside the real DeepSeek
Harness at the commit the plugin targets
(`0.2.1-alpha.1`, `5badb15009ae1756c3afe0ae0cef1faafc290ccc`).

It uses the Harness's own agent loop, tool registry and approval service, a
scripted model, the plugin loaded through its Cordis entry point, and
`gnap-server` over loopback HTTP. The tools are fakes that record whether they
ran.

```sh
packages/deepseek/harness-e2e/run.sh
```

The script clones the Harness into `.harness/` (or `HARNESS_DIR`), installs only
the packages the test needs, builds this repository, copies the spec into the
Harness tree and runs it there. It needs network access to GitHub and the npm
registry. The test is not part of `pnpm test`, because it imports Harness
packages.

## What it covers

- An uncovered call asks the owner, receives a key-bound grant and runs.
- The grant arrives within a second of approval.
- Covered calls run without asking; calls outside the grant ask again.
- Unprofiled tools and unmapped arguments are denied.
- Disposing one agent, and shutting down the whole Harness, revoke tokens.
- A child agent's parent is readable from `agent.session.header`.

## What it does not cover

- Credential isolation or enforcement outside the agent's process: there is
  no executor yet.
- PTC mode, where native tools are called from inside `run_code`.
- Child grants. The last test records the current gap: a delegated child,
  whose approval policy the Harness pins to `never`, is refused every profiled
  tool. It changes when child grants are derived from the parent's grant.
