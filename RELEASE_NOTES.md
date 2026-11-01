# RolePath Guard v1.0.0

First public release of a deterministic, **offline** Kubernetes RBAC authorization review engine.

- Explain effective allow/deny decisions with exact role, binding, principal and rule evidence.
- Model namespaced RoleBindings, ClusterRoleBindings, explicit identity groups, ServiceAccounts and transitive ClusterRole aggregation.
- Detect overbroad RBAC rules, access to Secrets, RBAC delegation and container execution permissions as **heuristic security findings**.
- Block policy changes which expand rights over an explicit query matrix.
- Enforce CI assertions about expected authorizations.
- Emit human-readable, JSON and SARIF 2.1.0 reports.
- Includes documented limitations, threat model and automated tests on Python 3.11–3.13 across Linux, Windows and macOS.

No cluster credentials or live API access are required. **Do not use this tool as a substitute for real-cluster SubjectAccessReview or admission control checks.**
