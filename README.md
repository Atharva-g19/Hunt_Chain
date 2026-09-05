# ScopeGuard

ScopeGuard is a deterministic target-authorization engine for security testing.

It takes a machine-readable bug-bounty scope definition and determines whether a supplied target is:

- `IN_SCOPE`
- `OUT_OF_SCOPE`
- `UNKNOWN`
- `CONFLICT`

The project is designed to make target authorization explicit, deterministic, explainable, and fail-closed.

---

## Project Goal

In security testing, one of the most important questions is:

> "Am I authorized to test this target?"

ScopeGuard separates authorization from reconnaissance and vulnerability testing.

A human first reads a bug-bounty program's policy and manually converts the authorized assets into a structured YAML scope definition.

ScopeGuard then evaluates targets against those rules.

```text
Bug-bounty policy
       |
       | Human interpretation
       v
Machine-readable YAML
       |
       v
ScopeGuard
       |
       v
Authorization decision