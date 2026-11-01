# Architecture (v1.0.0)

## Components

1. `parser.py`: size-limited local YAML/JSON input, strict RBAC object validation, immutable rule/role/binding primitives.
2. `engine.py`: computes role aggregation fixed point; identity expansion; exact permission decisions and matching evidence; heuristic risk labels; query-matrix differential.
3. `model.py`: dataclasses and input contracts.
4. `report.py`: deterministic text, JSON and SARIF output without filesystem or network side effects.
5. `cli.py`: typed command-line interface, output handling and documented exit codes.

## Data flow

```text
Local YAML/JSON --[validate]--> Role/Binding graph --[aggregate labels]--> Effective roles
                         |                                        |
        optional groups.json                                Principal/Request
                                                                  |
                            [resolve bindings + rule match] <-----+
                                           |
                        Evidence / Allow/Deny decisions
                                  |                 |
                  scans + risk signals         explicit baseline diff/assert
                                  \                 /
                                  JSON / Text / SARIF
```

No socket programming, cloud SDK, kubectl invocation, dynamic policy loading or API calls are used. The engine is stateless except the in-memory snapshot representation.

## Algorithmic behavior

The evaluator loops through bindings and applicable rules; complexity for one query is O(B * S + B * R), where B is binding count, S the subjects per binding, and R the rules in the referenced role. Aggregated ClusterRole rules are calculated until no new rules appear (bounded by aggregate role count). Query matrices are limited to 10,000. This is intended for code-review snapshots and not enterprise-scale inventories.

## Release contract

A release is built by GitHub Actions after CI succeeds on `main`. `workflow_run` verifies successful push runs from the same repository and checks out the validated commit. The archive contains documentation, tests, examples and package source. Publication attaches a checksum to allow integrity checks. Workflow permissions are limited to read for CI and `contents: write` for the release workflow.
