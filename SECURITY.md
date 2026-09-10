# Security policy

AGNAP specifies authorization decisions and credential isolation. Ambiguities
that permit broader authority than intended can therefore be security issues
even when no implementation code is present.

## Supported versions

Security updates are made against the latest published specification version.

| Version | Supported |
| ------- | --------- |
| 0.1.x   | Yes       |

## Reporting a vulnerability

Do not open a public issue for a suspected vulnerability. Use
[GitHub's private vulnerability reporting](https://github.com/daevmithran/agnap/security/advisories/new)
to share the details with the maintainer.

Include, where possible:

- The affected file, schema, operation, or requirement.
- The authority an issuer appears to grant.
- The broader behavior an implementation could accept.
- A minimal message or sequence demonstrating the problem.
- The security impact and any suggested correction.

You should receive an acknowledgement within seven days. The maintainer will
assess the report, coordinate a fix and disclosure when warranted, and credit
reporters who wish to be named.

## Specification security scope

Examples include:

- A schema accepting authority outside its documented closed world.
- Ambiguous containment, temporal validity, ceiling, or revocation semantics.
- A signature profile that does not bind a security-relevant request field.
- A delegation shape that permits widening, replay, or lineage confusion.
- A message inconsistency that causes independent implementations to make
  different authorization decisions.
- A response shape that could expose a credential or secret to an agent.

Feature requests, missing future functionality, editorial issues without a
security consequence, and vulnerabilities in unpublished implementation code
can be reported through the regular issue templates.
