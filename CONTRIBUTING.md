# Contributing

Thank you for helping improve deterministic Kubernetes RBAC security review.

1. Open a well-scoped issue describing expected semantics, citing the Kubernetes RBAC reference where applicable.
2. Create changes on a feature branch. Avoid unrelated formatting and generated files.
3. Add positive, negative and edge-case unit tests; modify `docs/SEMANTICS.md` if authorization behavior changes.
4. Run `python -m pip install -e '.[test]'` and `python -m unittest discover -s tests -v`, plus `coverage run -m unittest discover -s tests`.
5. Open a PR including threat model impact, new/changed CLI flags and sample output.

Never commit kubeconfig files, tokens, production identity mappings or private manifests. Security-sensitive reports should follow `SECURITY.md`.
