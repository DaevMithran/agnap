# Delegation flow

This is an informative view of AGNAP's planned parent-to-child delegation
flow. The normative wire formats are defined in
[`schema/delegation.json`](../packages/specs/schema/delegation.json).

Each child is a distinct GNAP client instance with its own key. The parent
authorizes the child to request a subset of its authority, while the
Authorization Server verifies containment and the vault enforces the resulting
grant.

When resource-owner interaction is required, the runtime can hand the
AS-generated interaction to a trusted adapter for delivery through an existing
user channel. The channel carries the interaction but does not approve the
grant. Approval remains bound to the Authorization Server.

```mermaid
sequenceDiagram
    autonumber
    actor RO as Resource Owner
    participant P as Parent agent
    participant C as Child agent
    participant AS as GNAP AS
    participant V as Vault (GNAP RS1)
    participant DAS as Downstream AS
    participant DRS as Downstream Resource Server

    P->>AS: Request root authority for vault operations
    alt Immediate approval
        AS-->>P: Key-bound root token and delegation reference
    else Interaction required
        AS-->>P: Interaction details and continuation handle
        P-->>RO: Deliver AS interaction via trusted user channel
        RO->>AS: Approve or narrow
        P->>AS: Continue root grant request
        AS-->>P: Key-bound root token and delegation reference
    end

    C->>C: Generate child key
    C->>P: Send child public-key thumbprint
    P-->>C: Sign delegation assertion for narrower authority
    C->>AS: Request child grant with assertion and child key
    AS->>AS: Verify parent, signature, containment, depth, and expiry
    alt Requested authority is contained
        AS-->>C: Key-bound child token and signed receipt
    else Widening is rejected by policy
        AS-->>C: Deny child grant
    else Widening is escalated to the owner
        AS-->>C: Interaction details and continuation handle
        C-->>RO: Deliver AS interaction via trusted user channel
        RO-->>AS: Approve or narrow
        C->>AS: Continue child grant request
        AS-->>C: Key-bound child token and escalated receipt
    end

    C->>V: Operation, child token, arguments, and key proof
    V->>AS: Introspect child token
    AS-->>V: Active authority, bound key, lineage, and credential reference
    V->>V: Check arguments and reserve shared ceiling
    opt Downstream credential must be obtained or refreshed
        V->>DAS: Request credential
        DAS-->>V: Credential accepted by downstream service
    end
    V->>DRS: Execute with downstream credential
    DRS-->>V: Result
    V->>V: Settle ceiling and record audit event
    V-->>C: Result only
```

The important invariants are:

- The child token is bound to the child's key, not the parent's.
- A contained child grant does not require resource-owner interaction.
- Widening is rejected unless the root policy allows owner escalation.
- A child cannot approve its own widening.
- Descendants share the ancestor's ceilings rather than receiving copies.
- Revoking an ancestor makes its descendants unusable at the vault.
- Downstream credentials never enter either agent runtime.
