# `@agnap/access-types`

Built-in GNAP access types for agent authorization. The first exported profile,
`agent_operation`, authorizes tool and API calls by operation name and argument:

```ts
import { agentOperationHandler, covers } from '@agnap/access-types';
// The focused subpath is also available as @agnap/access-types/agent-operation.
```

```json
{
  "type": "agent_operation",
  "operations": {
    "github.pull_request.create": {
      "repository": { "exact": "acme/api" },
      "title": { "wildcard": true }
    }
  }
}
```

The model is closed-world: unnamed operations and arguments are denied. This
package currently implements scalar `exact` and `wildcard` constraints and
exports parsing, call-coverage, containment, and its `AccessTypeHandler`.

`agent_operation` is enough for most tool-call authorization because new tools
are represented as new operation names. It is not the only access type the
server can support. Add a separate handler when a use case needs materially
different semantics rather than more operation arguments.

## Containment

Containment is what makes narrowing safe. Exact access is contained by the same
exact value or a wildcard. A wildcard is contained only by a wildcard. The
authorization server uses this rule when approving less access than the client
requested, and resource servers use call coverage to check concrete arguments.

Dropping an operation or argument narrows access. Adding one widens it. Replacing
a wildcard with an exact scalar narrows it; replacing an exact value with a
wildcard or a different value does not.

## Call coverage

A concrete call is allowed only when:

- the operation exists in the access object;
- every argument supplied by the call is named; and
- every supplied value satisfies its exact or wildcard constraint.

An access object bounds which arguments may be supplied; it does not require a
call to supply every argument named in the grant. Requiredness belongs to the
tool schema or application protocol, not to the grant constraint.

The deliberately small constraint set keeps containment decidable and approval
text understandable. Richer concepts such as conserved spending or rate limits
should become another access type when they require different state and
containment semantics, rather than an embedded general-purpose policy language.
