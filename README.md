<div align="center">

# RolePath Guard

**Offline Kubernetes RBAC entitlement analysis, regression gates & evidence-driven least-privilege reviews**

[![CI](https://github.com/felipewatter/rolepath-guard/actions/workflows/ci.yml/badge.svg)](https://github.com/felipewatter/rolepath-guard/actions/workflows/ci.yml)
[![Python](https://img.shields.io/badge/Python-3.11%2B-blue)](https://www.python.org/)
[![License](https://img.shields.io/badge/License-MIT-green)](LICENSE)
[![Status](https://img.shields.io/badge/version-v1.0.0-informational)](CHANGELOG.md)

**[Documentation](docs/ARCHITECTURE.md) · [RBAC semantics](docs/SEMANTICS.md) · [Threat model](docs/THREAT_MODEL.md) · [Security policy](SECURITY.md) · [Examples](examples/)**

</div>

> **Scope:** Defensive, *offline*, least-privilege inspection of local Kubernetes `rbac.authorization.k8s.io/v1` manifests. No Kubernetes credentials, outbound traffic, Kubernetes API calls, discovery, or attempts to modify clusters. This is **not** a substitute for a live `SubjectAccessReview` or a complete Kubernetes authorization audit.

## Why another RBAC project?

A `RoleBinding` can reference a namespaced `Role` or a cluster-scoped `ClusterRole`. A `ClusterRoleBinding` can grant cluster-level permissions. Understanding the *effective* access of a specific principal requires following role references, group membership, namespace boundaries, special service-account groups and the aggregated `ClusterRole` graph, then evaluating a concrete request. Naive string grep cannot do this reliably.

RolePath Guard is deliberately **not** a cluster scanner. Compared with established tools such as CyberArk KubiScan, Aqua `kubectl-who-can` and Palo Alto Networks `rbac-police`, it emphasizes **fully offline, deterministic entitlement explanations and explicit regression matrices in CI**. This distinction is about intended scope, not an unsupported claim of feature superiority.

## Features

| Capability | Outcome | Scope / limitation |
| --- | --- | --- |
| Effective access | Evidence explaining **which role, binding and subject** permit an action | Only supplied manifests and explicit group map |
| Namespace boundaries | RoleBinding applies within its namespace, ClusterRoleBinding applies cluster-wide | Callers must set namespace accurately for namespaced requests |
| User, Group, ServiceAccount | Group mapping, authenticated/unauthenticated defaults and SA synthetic groups | No OIDC/identity-provider lookups |
| ClusterRole aggregation | OR selectors, matchLabels and matchExpressions, transitive fixed-point resolution | Offline approximation; live controller state not queried |
| Kubernetes resource rules | Verbs, API groups, resources, subresources, `resourceNames` | Explicit name filtering required for list/watch, as on the API server |
| Non-resource paths | Exact, global and trailing `/*` patterns | ClusterRoleBinding only |
| Risk detection | Heuristics for secrets access, dangerous wildcards, delegation and workload execution | Severity is risk signal, **not** vulnerability proof |
| Access regression | Compare baseline and candidate on an explicit JSON query matrix | Only queries in matrix; not universal equivalence |
| Assertions | Enforce expected allow/deny behavior in CI | Exit 1 on failed assertion |
| Reporting | Text, structured JSON, SARIF 2.1.0 | SARIF emitted for scan findings |
| Input controls | 2 MiB max input, object and query bounds, SafeLoader, strict validation | Local YAML/JSON only, no templating |
| Portable | Python 3.11+, Linux, macOS, Windows | Requires PyYAML |

## Quick start

```bash
# Python >=3.11, virtualenv recommended
python -m venv .venv
# Linux/macOS: source .venv/bin/activate
# Windows: .venv\\Scripts\\activate
python -m pip install -e .
rolepath --help

# Example 1: Secure baseline, expected to be clean
rolepath scan --snapshot examples/baseline.yaml --fail-on high

# Example 2: Illustrative candidate contains added Secret-read access
rolepath scan --snapshot examples/candidate.yaml --format json --fail-on high

# Example 3: Show exact evidence for an authorization decision
rolepath can-i --snapshot examples/baseline.yaml \\
  --groups examples/groups.json \\
  --principal User:alice@example.test \\
  --verb get --resource configmaps --namespace apps

# Example 4: Fail CI if any query gained access
rolepath diff --baseline examples/baseline.yaml \\
  --candidate examples/candidate.yaml \\
  --groups examples/groups.json --queries examples/queries.json \\
  --fail-on-expansion

# Example 5: Assert expected rights of declared identities
rolepath assert --snapshot examples/baseline.yaml \\
  --groups examples/groups.json --checks examples/invariants.json

# Example 6: Generate SARIF for review tools
rolepath scan --snapshot examples/candidate.yaml \\
  --format sarif --fail-on none --output rolepath.sarif
```

The candidate scan and candidate-vs-baseline diff intentionally return **exit 1** to demonstrate security gates. Change the baseline/candidate inputs or thresholds to run them without failing.

## Command reference

### `scan`

```text
rolepath scan --snapshot FILE [--format text|json|sarif]
    [--fail-on none|low|medium|high|critical] [--output FILE]
```

Walks bindings and their effective roles, resolves ClusterRole aggregation, and classifies risk heuristically. `--fail-on high` is the default. JSON findings include rule ID, severity, subject, binding, role, rule index, message and caveat. `--fail-on none` makes a report-only scan.

Current built-in risk IDs:

| Rule | Signal | Typical severity |
| --- | --- | --- |
| RPG001 | Wildcard verb + resource + API group | High / Critical for cluster-wide |
| RPG002 | Binding to broad built-in group | High / Critical for cluster-wide |
| RPG003 | May read Secrets | High / Critical for cluster-wide |
| RPG004 | RBAC escalation, binding or impersonation operations | High |
| RPG005 | Pod exec/attach operations | High |
| RPG006 | Workload creation | Medium |
| RPG007 | Wildcard non-resource access | Medium |

**Interpretation:** Risk rules prioritize evidence for human review, not an exploitable attack sequence. A `rule` is not equivalent to an effective command on a cluster after admission and other authorization checks.

### `can-i`

```text
rolepath can-i --snapshot FILE --principal User:alice --verb get
    --resource pods [--api-group ""] [--namespace apps] [--name web-1]
    [--name-filter] [--groups FILE]

rolepath can-i --snapshot FILE --principal ServiceAccount:monitoring:bot
    --verb get --non-resource-url /healthz
```

The decision report includes an `allowed` boolean and **all matching evidence** (`binding`, `role`, `subject`, `rule_index`). For resourceName-restricted list/watch operations, provide `--name pod-1 --name-filter` to model a `metadata.name` field selector. An omitted namespace means a *cluster-scope* authorization request; it is not shorthand for all namespaces.

### `diff`

```text
rolepath diff --baseline PRE.yaml --candidate POST.yaml \\
   --queries examples/queries.json [--groups examples/groups.json] \\
   [--fail-on-expansion] [--output diff.json]
```

The query matrix is a JSON array of `Request` objects. Each request supplies `principal`, `verb`, and either `resource` (plus optional `api_group`, `namespace`, `resource_name`, `name_filter`) or `non_resource_url`. **Result is relative to exactly the supplied query matrix**, not a general statement that two Kubernetes policies are equivalent. `expansions` and `removals` summarize changed *boolean* decisions; evidence changes without an allow/deny transition are not labeled as expansions.

### `assert`

```text
rolepath assert --snapshot CLUSTER.yaml --checks invariants.json \\
   [--groups groups.json] [--output report.json]
```

The checks file contains the same query schema plus a mandatory boolean `allowed`. Any mismatch returns exit 1, supporting change reviews and security-as-code practices.

### Exit codes

| Code | Meaning |
| --- | --- |
| 0 | Success / clean threshold / all assertions passed / permission allowed |
| 1 | Detected risk at selected threshold, denied `can-i`, new access (with `--fail-on-expansion`), or failed assertion |
| 2 | Invalid input, missing role reference, YAML/JSON parse error, or filesystem error |

A `can-i` exit code of 1 means a denial and is *not*, by itself, a vulnerability.

## Threat model and trust boundaries

**Inputs are untrusted local files.** The tool parses YAML with PyYAML SafeLoader (never constructs arbitrary Python objects), rejects unknown Kubernetes resource kinds, validates names, constrains list lengths and file sizes, and never reads credentials or executes input. Static snapshots can still be unrepresentative or stale. See [Threat Model](docs/THREAT_MODEL.md) for out-of-scope behavior, false-positive and false-negative handling, and assumptions.

### Semantics that deserve special attention

1. A `RoleBinding` to a `ClusterRole` grants its resource permissions **only inside the binding namespace**; it does not make cluster-scoped requests available through that binding.
2. A `ClusterRoleBinding` may grant rights in any namespace and at cluster scope. The manifest snapshot does not enumerate namespaces.
3. `resourceNames` cannot restrict `create` and `deletecollection` and requires a `metadata.name` selector for `list` and `watch`.
4. Aggregated `ClusterRole` rules are derived from other labeled roles, not treated as static user-supplied rules. The analyzer computes transitive aggregation for supplied manifests.
5. RBAC is additive: there are no deny rules. A `denied` analysis means **no allow matched in the provided snapshot**, not definitive denial in a real cluster.
6. ServiceAccount identity `ServiceAccount:ns:name` and corresponding Kubernetes username `User:system:serviceaccount:ns:name` are modeled as aliases.

More detail and limitations: [Semantics](docs/SEMANTICS.md).

## Testing & quality gates

```bash
python -m pip install -e '.[test]'
python -m unittest discover -s tests -v
coverage run -m unittest discover -s tests
coverage report -m
python -m compileall -q src tests
python -m pip check
python -m build
```

GitHub Actions runs unittest, syntax checks, reproducible examples and packaging across Python 3.11/3.12/3.13 on Linux, Windows and macOS. The code is intentionally written with a small dependency surface; dependency upgrades must be reviewed in CI.

## Repository layout

```text
src/rolepath_guard/       Pure parser, evaluator, CLI and SARIF formatter
examples/                 Synthetic safe and intentionally riskier manifests
  baseline.yaml           Small read-only configuration access
  candidate.yaml          Same plus Secret reads (for gate demonstration)
  groups.json             Synthetic explicit external group membership
  queries.json            Explicit regression query matrix
  invariants.json         Authorization assertions
 tests/                   Unit tests for parsing, scope, aggregation, risk, CLI
 docs/                    Architecture, model semantics, threat model, test matrix
 .github/workflows/       CI, release publication after successful CI
```

## Secure development, disclosure and contribution

- **No credentials in examples**; identities use reserved `.test` addresses.
- Security problems should use the process in [SECURITY.md](SECURITY.md), not public issues with sensitive data.
- Contributions require tests and documentation, including changed assumptions for Kubernetes authorization.
- See [CONTRIBUTING.md](CONTRIBUTING.md) and [CHANGELOG.md](CHANGELOG.md).
- Licensed under [MIT](LICENSE).

## Sources and prior art

- [Kubernetes — Using RBAC Authorization](https://kubernetes.io/docs/reference/access-authn-authz/rbac/)
- [Kubernetes — RBAC good practices](https://kubernetes.io/docs/concepts/security/rbac-good-practices/)
- [Kubernetes — RBAC API reference](https://kubernetes.io/docs/reference/kubernetes-api/rbac/)
- [SARIF specification v2.1.0](https://docs.oasis-open.org/sarif/sarif/v2.1.0/)
- [CyberArk KubiScan](https://github.com/cyberark/KubiScan)
- [Aqua kubectl-who-can](https://github.com/aquasecurity/kubectl-who-can)
- [Palo Alto Networks rbac-police](https://github.com/PaloAltoNetworks/rbac-police)

These links describe references and prior art, **not** certification, an endorsement, or a claim of formal verification of live-cluster behavior.

---

**Maintainer:** [felipewatter](https://github.com/felipewatter) · **Release:** v1.0.0
