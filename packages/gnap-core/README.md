# `@agnap/gnap-core`

Protocol building blocks shared by GNAP clients, authorization servers, and
resource servers:

- RFC 9635 and RFC 9767 wire types generated from `@agnap/specs`, with Ajv runtime validators;
- the RFC 9421 HTTP Message Signatures profile;
- Ed25519 key utilities; and
- the registry seam for application-defined GNAP access types.

It performs no HTTP I/O, storage, or authorization policy.

## Access types

GNAP access is deliberately application-defined. `gnap-core` does not restrict
a deployment to `agent_operation`. An access type supplies an
`AccessTypeHandler` that parses its wire object and decides whether requested
access is contained by granted access.

```ts
import { AccessTypeRegistry } from '@agnap/gnap-core';
import { agentOperationHandler } from '@agnap/access-types';

const accessTypes = new AccessTypeRegistry([
  agentOperationHandler,
  applicationAccessTypeHandler, // hypothetical; supplied by your application
]);
```

Use a new type when the authorization semantics are genuinely different, such
as conserved spending, rate limits, or domain-specific delegation. Use another
operation inside `agent_operation` when only the operation name and arguments
change.

Each handler must fail closed on malformed or unsupported input and define
containment so an owner or policy can safely narrow a request.

The handler contract has three responsibilities:

1. expose a unique `type` string;
2. parse and validate access objects of that type; and
3. decide whether one valid object contains another.

The server uses the same registry for initial requests, owner narrowing, and
RFC 9767 requested-access checks. This keeps extension logic out of the generic
GNAP state machine while ensuring every narrowing decision uses the type's own
semantics.
