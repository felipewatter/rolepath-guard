# RolePath Guard v1.0.0 — Local Validation Report

**Validation date:** 2026-11-01 (UTC). **Status:** local verification complete. Remote CI and release status must be verified via the GitHub Actions and Releases links below; these are live external records.

## Verified locally

| Check | Outcome |
|---|---|
| Standard-library unittest suite | PASS: 87 test methods |
| Differential cases in test_properties.py | PASS: 1,350 deterministic randomized cases (seeded) |
| Coverage (statements and branches combined) | 89% overall as measured by coverage.py |
| Compilation | PASS: `python -m compileall -q src tests` |
| Wheel build | PASS: rolepath_guard-1.0.0-py3-none-any.whl |
| Installed-wheel CLI smoke test | PASS: scan clean sample, assertions, SARIF serialization |
| YAML workflow parse checks | PASS (structural local parsing; GitHub execution not yet performed) |
| GitHub Actions Linux/Windows/macOS matrix | See the [live CI execution history](https://github.com/felipewatter/rolepath-guard/actions/workflows/ci.yml) for the latest outcome |
| GitHub release | See [published releases](https://github.com/felipewatter/rolepath-guard/releases) and verify checksums and commit tags |

## Environment-specific caveat

A global `python -m pip check` on the host reported an unrelated pre-existing dependency mismatch: moviepy 2.2.1 requires Pillow below 12 while installed Pillow is 12.3.0. This is **not** a RolePath Guard dependency mismatch; its declared runtime dependency is PyYAML 6.0.2 or later within major version 6. Fresh GitHub CI installs into clean runners to validate dependencies independently.

## Security model

The analyzer processes only local, bounded YAML/JSON RBAC manifests. It does not query Kubernetes clusters or verify admission controllers. Its results are authoritative only relative to the supplied snapshots, group map and query matrix. Rule findings are risk heuristics, not proof of exploitability or formal certification.

## Notes

The test log and coverage table accompany the deliverable. The archive and installed wheel checksums are published separately. The local validation figures above describe the packaged v1.0.0 source. Always inspect the live GitHub CI conclusions and release artifacts before treating a remote build as verified.
