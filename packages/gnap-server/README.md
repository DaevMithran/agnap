# `@agnap/gnap-server`

An RFC-oriented GNAP authorization server library with a Fetch handler and a
small Node runner. It implements grant requests, continuation, token
management, RFC 9767 introspection, resource-server registration, and an
in-memory store for local development.

The server is generic over access types and policy. Its CLI registers
`agent_operation` for the local demo, but applications can register additional
handlers:

```ts
import { agentOperationHandler } from '@agnap/access-types';
import { createServer, MemoryStore } from '@agnap/gnap-server';

const server = createServer(
  {
    issuer: 'https://as.example/',
    registry: resourceServers,
    accessTypes: [
      agentOperationHandler,
      applicationAccessTypeHandler, // hypothetical; supplied by your application
    ],
    decision,
  },
  new MemoryStore(),
);
```

A single grant request may contain multiple access objects and multiple access
types. Every type must have a registered handler, and the selected resource
server must be registered for every type it introspects.

## Grant lifecycle

Grants are created by a signed client request; they are not static server
configuration. The decision layer can issue, deny, or leave the request pending
for its owner. On approval, the owner may return the requested access or a
narrower subset. Widening is rejected using the registered handlers'
containment rules.

Standing policy and issued grants are different things. A `DecisionStep`
evaluates requested access and returns one of three protocol outcomes:

- `issue`, optionally with narrower access;
- `pending`, so an owner can decide later; or
- `deny`.

The included `fixedList()` decision is useful for tests and fixed deployments;
`pendingOwner` sends every request through owner interaction. Applications can
provide their own decision implementation without changing the GNAP protocol.
After issuance, resource servers check the issued access rather than rerunning
the server's standing policy.

A pending grant tells the client how long to wait before continuing
(`continueWaitSeconds`, default 5; `gnap-server serve --continue-wait`), and an
earlier continuation gets `too_fast`. Once the owner approves or denies, the
next continuation is answered at once.

Pending and approved grants expire if continuation is not completed. Issued
tokens have their own expiry and management handle. The in-memory store removes
expired state lazily, binds continuation and revocation to the client key, and
keeps only token hashes for lookup. A durable store must preserve the same
atomic state transitions.

Owner approval may drop access objects, operations, or arguments, or replace a
wildcard with an exact value when the corresponding access-type handler says
that is narrower. It may never add authority that the client did not request.

The `/local/grants` routes and `gnap-server owner` command are a development
extension, not GNAP endpoints. The in-memory store and loopback HTTP runner are
appropriate for tests and demos; production deployments need durable atomic
storage, HTTPS, real owner interaction, and managed key custody.
