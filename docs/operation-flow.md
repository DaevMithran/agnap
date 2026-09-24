# Authorization and execution sequence

This is the detailed version of the simplified AGNAP flow in the project
README. It keeps the Authorization Server, vault, downstream authorization
system, and downstream resource server visible as separate protocol roles.

```mermaid
sequenceDiagram
    actor RO as Resource Owner
    participant R as Agent Runtime
    participant C as Agent
    participant AS1 as GNAP AS
    participant V as Vault (RS1)
    participant AS2 as Downstream AS
    participant RS2 as Downstream RS

    RO->>R: Describe and confirm session permission
    R->>C: Start agent with its own key

    C->>AS1: Request access to vault operation
    alt Covered by initial permission
        AS1-->>C: Key-bound token
    else Needs owner decision
        AS1-->>C: Interaction + continuation
        C-->>RO: Interaction via trusted channel
        RO->>AS1: Approve or narrow
        C->>AS1: Continue grant
        AS1-->>C: Key-bound token
    end

    C->>V: Operation + token + key proof
    opt Token introspection
        V->>AS1: Introspect
        AS1-->>V: Rights, audience, key
    end
    V->>V: Check rights, arguments, remaining usage

    opt No valid downstream credential held
        V->>AS2: Obtain or refresh credential
        AS2-->>V: Credential
    end
    V->>RS2: Operation + downstream credential
    RS2-->>V: Result or denial
    V-->>C: Result only
```
