# Verification Matrix

Test commands:

```bash
python -m pip install -e '.[test]'
python -m unittest discover -s tests -v
coverage run -m unittest discover -s tests
coverage report -m
python -m compileall -q src tests
python -m build
python -m pip check
```

| Feature | Regression coverage |
| --- | --- |
| YAML/JSON parsing | Multi-doc, List, strict metadata, invalid refs, wrong versions, malformed and oversize inputs |
| Binding scopes | RoleBinding vs ClusterRoleBinding and RoleBinding → ClusterRole |
| Identity | Users, Groups, ServiceAccounts, system groups and SA username alias |
| Rules | apiGroups, verbs, wildcard resources, subresources, URL patterns and resourceNames |
| Aggregation | Match labels, expressions, nested resolution, cycles and invalid selectors |
| Reports | JSON/text/SARIF output, stable IDs |
| Risk signals | Wildcards, Secrets, pod exec, broad audiences, escalate |
| Differential | Expansion/removal/no change and max query cap |
| CLI | `scan`, `can-i`, `diff`, `assert`, threshold semantics and error exit codes |

CI matrix: Ubuntu, Windows and macOS with CPython 3.11, 3.12 and 3.13. Results shown in the GitHub Actions run are authoritative for the published commit; local run evidence is recorded separately in validation report.
