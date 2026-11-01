# Modeled Kubernetes RBAC semantics

| Subject or policy element | Modeled behavior |
|---|---|
| `Role` | Namespaced rule container; default namespace when omitted |
| `ClusterRole` | Global rule container, referenced by ClusterRoleBinding or namespaced RoleBinding |
| `RoleBinding` | Restricts grants to its namespace even for ClusterRole rules |
| `ClusterRoleBinding` | Grants global/namespaced rights from ClusterRole |
| `User` | Username plus built-in authenticated/unauthenticated group |
| `Group` | Explicit group identity or supplied external group membership |
| `ServiceAccount` | Namespace/name identity, corresponding canonical username and default SA groups |
| `apiGroups`, `resources`, `verbs` | Exact value or `*`; subresource `pods/*` and `*/status` matching |
| `resourceNames` | Exact target match, list/watch require `name_filter`, create/deletecollection denied |
| `nonResourceURLs` | `*`, exact path, or suffix `/*`, only via ClusterRoleBinding |
| `aggregationRule` | OR over selectors, AND within match conditions, transitive rules from selected ClusterRoles |
| RBAC authorization | Additive, no deny evaluation |

## Explicit limitations

- **No live cluster state.** Default bootstrapping roles, controllers, dynamically updated labels, admissions, webhooks, Node authorizer, ABAC, impersonation headers and resource existence cannot be inferred from static input.
- **Missing group data.** Supply groups.json for users; OIDC, external provider and system groups beyond modeled built-ins are not discovered.
- **Rules may overstate or understate reality.** The engine assumes the request scope and Kubernetes resource/subresource name supplied by the operator are correct.
- **No wildcard namespace scan.** `namespace=null` means a cluster-scope request, not `all namespaces`.
- **No exhaustive policy diff.** Regressions only identify allow/deny changes in a user-defined finite query matrix. Equivalent decisions with different evidence are not identified as changes.
- **Aggregated-role controller state.** Static transitive closure approximates aggregation semantics; does not reproduce all asynchronous controller behaviors.
- **Path patterns.** Only RBAC non-resource exact and terminal `/*` syntax is supported.
- **Risk heuristics.** A flagged Secret read or pod/exec privilege is a review cue; `resourceNames`, admission controls, runtime context and authorization webs may affect exploitability.
- **Unresolved references fail closed.** Supply the full relevant role definitions; manifest fragments may not contain all referenced roles.

See official documentation: https://kubernetes.io/docs/reference/access-authn-authz/rbac/
