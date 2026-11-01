# Threat Model

## Protected assets

- Integrity of authorization test results consumed by a CI gate.
- Confidentiality of input snapshots (may contain internal role names and group assignments).
- Availability of local analysis (bounded inputs prevent common resource exhaustion cases).

## Trust boundaries

1. **Untrusted source files:** YAML/JSON from a developer workspace or pull request must never be executed. PyYAML SafeLoader does not instantiate arbitrary Python classes; file bytes, object counts, rule counts, selector lists and query matrices are limited.
2. **Analysis process:** pure in-memory model, no networking, no cluster client, no subprocess, no runtime eval/exec, no code templates.
3. **Report destination:** output paths are provided by the caller; only run on trusted workspaces to avoid replacing unintended files.
4. **GitHub workflow:** untrusted PRs use read-only checkout; write permission exists only in post-CI release job for the main branch and same-repository run.

## Out of scope / residual risks

- Kubernetes version changes, APIServer authorization configuration, real identities, webhook authorizers and admission chains.
- Denial-of-service from pathological YAML parse complexity within file-size bounds; memory, CPU and filesystem limits should be set by calling automation.
- Running analysis with privileges beyond what the host/workspace requires.
- Handling live credentials or production secrets. Do not place secrets in Git.
- Completeness of arbitrary query matrices: a missed query can hide an expansion.

## Security guarantees

- No outbound traffic from application code.
- No cluster mutations.
- Parse failures return exit 2 instead of silently granting access.
- Authorization evaluation requires explicit principal, verb and target; evidence maps to binding/role/rule.
- Release checksums detect accidental archive corruption but are **not cryptographic signatures** or provenance attestations.
