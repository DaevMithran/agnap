# Delegation flow

This is an informative view of AGNAP's planned parent-to-child delegation
flow. The normative wire formats are defined in
[`schema/delegation.json`](../packages/specs/schema/delegation.json).

The user or organization can require a new decision for every root task or set
a small initial permission for verified agent instances. Zero permission is
the recommended default, not a protocol requirement. In both cases, the AS
issues a separate key-bound grant to the running instance. Each child is a
distinct GNAP client instance with its own key. The parent requests the
permission that the child needs. It does not grant that permission. The runtime
proves the parent and child relationship. The Authorization Server derives the
final child grant from the request, the parent grant, the owner's delegation
mode, and the shared task limits. The vault enforces the grant.

When resource-owner interaction is required, the runtime can hand the
AS-generated interaction to a trusted adapter for delivery through an existing
user channel. The channel carries the interaction but does not approve the
grant. Approval remains bound to the Authorization Server.

```mermaid
sequenceDiagram
    autonumber
    actor RO as Resource Owner
    participant APP as Application
    participant RT as Agent runtime
    participant P as Parent agent
    participant C as Child agent
    participant AS as GNAP AS
    participant V as Vault (GNAP RS1)
    participant DRS as Downstream Resource Server

    APP->>RT: Start the root task
    P->>AS: Request root authority for vault operations
    alt Request is covered by an initial owner permission
        AS-->>P: Key-bound root token and delegation reference
    else The root task needs a new owner decision
        AS-->>P: Interaction details and continuation handle
        P-->>RO: Deliver AS interaction via trusted user channel
        RO->>AS: Approve or narrow
        P->>AS: Continue root grant request
        AS-->>P: Key-bound root token and delegation reference
    end

    P->>RT: Start child and request its permission
    RT->>C: Start child instance
    C->>C: Generate child key
    C-->>RT: Send child public-key thumbprint
    RT->>AS: Prove parent, child, and child key
    RT-->>P: Send child public-key thumbprint
    P-->>C: Sign assertion for the requested child permission
    C->>AS: Request child grant with assertion and child key
    AS->>AS: Verify runtime evidence, parent, signature, containment, depth, and expiry
    alt Manual delegation mode
        AS-->>C: Interaction details and continuation handle
        C-->>RO: Deliver AS interaction via trusted user channel
        RO-->>AS: Approve, narrow, or reject
        C->>AS: Continue child grant request
        AS-->>C: Key-bound child token or denial
    else Automatic mode and request is within grant and limits
        AS-->>C: Key-bound child token and signed receipt
    else Automatic mode and additional permission can be requested
        AS-->>C: Interaction details and continuation handle
        C-->>RO: Deliver AS interaction via trusted user channel
        RO-->>AS: Approve or narrow
        C->>AS: Continue child grant request
        AS-->>C: Key-bound child token and escalated receipt
    else Step-up is not allowed
        AS-->>C: Deny child grant
    end

    C->>V: Operation, child token, arguments, and key proof
    V->>AS: Introspect child token
    AS-->>V: Active authority, bound key, lineage, and credential reference
    V->>V: Check arguments and reserve shared ceiling
    V->>V: Resolve or obtain the downstream credential
    V->>DRS: Execute with downstream credential
    DRS-->>V: Result
    V->>V: Settle ceiling and record audit event
    V-->>C: Result only
```

The important invariants are:

- The child token is bound to the child's key, not the parent's.
- The AS issues a child grant only after it receives matching runtime evidence.
- The parent requests child permission but cannot grant it.
- Automatic mode does not require owner interaction for a child request within
  the parent grant, maximum depth, and shared task limits.
- Manual mode requires owner interaction for every child grant.
- Additional permission is rejected unless the owner allows a new approval.
- A child cannot approve its own widening.
- Descendants share the ancestor's ceilings rather than receiving copies.
- Revoking an ancestor makes its descendants unusable at the vault.
- Downstream credentials never enter either agent runtime.

The runtime-evidence message is part of the planned design. The current schema
does not yet define its wire format or trusted transport.
