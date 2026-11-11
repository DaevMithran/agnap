# Harness end-to-end test

`agnap-integration.spec.ts` runs `@agnap/deepseek` inside the real DeepSeek
Harness at the commit the plugin targets
(`0.2.1-alpha.1`, `5badb15009ae1756c3afe0ae0cef1faafc290ccc`).

It uses the Harness's own agent loop, tool registry and approval service, a
scripted model, the plugin loaded through its Cordis entry point, `gnap-server`
over loopback HTTP, and a scripted owner built on `@agnap/owner` whose
decisions are signed with the owner key. The tools are fakes that record
whether they ran.

```sh
packages/deepseek/harness-e2e/run.sh
```

The script clones the Harness into `.harness/` (or `HARNESS_DIR`), installs only
the packages the test needs, builds this repository, copies the spec into the
Harness tree and runs it there. It needs network access to GitHub and the npm
registry. The test is not part of `pnpm test`, because it imports Harness
packages.

## What it covers

- An uncovered call waits for the owner, who approves outside the Harness; the
  Harness approval prompt is never used.
- The token arrives on the plugin's next poll after approval.
- Covered calls run without asking; calls outside the grant ask again, and a
  denial stops the tool.
- Unprofiled tools and unmapped arguments are denied.
- Disposing one agent, and shutting down the whole Harness, revoke tokens.
- The owner sees a subagent named with its parent; each child has its own key.
- A delegated child, whose approval policy the Harness pins to `never`, can be
  granted access by the owner.

## What it does not cover

- Credential isolation or enforcement outside the agent's process: there is
  no executor yet.
- PTC mode, where native tools are called from inside `run_code`.
- Child grants derived from the parent's grant. A child's grant is still a
  separate owner decision.
