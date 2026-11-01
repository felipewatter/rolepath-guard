"""Offline CLI and deterministic exit codes (0 clean, 1 finding, 2 invalid input)."""
from __future__ import annotations
import argparse
import json
import sys
from pathlib import Path
from .engine import Analysis, compare
from .model import PolicyError, Request
from .parser import MAX_BYTES, read_snapshot
from .report import render

SEVERITIES = {'low': 1, 'medium': 2, 'high': 3, 'critical': 4}

def _load_json(path: str) -> object:
    p = Path(path)
    if not p.is_file() or p.stat().st_size > MAX_BYTES:
        raise PolicyError('JSON query/check file absent or too large')
    try:
        return json.loads(p.read_text(encoding='utf-8'))
    except (UnicodeError, json.JSONDecodeError) as e:
        raise PolicyError(f'invalid JSON: {e}') from e

def _analysis(path: str, groups: str | None = None) -> Analysis:
    gm = _load_json(groups) if groups else None
    if gm is not None and not isinstance(gm, dict):
        raise PolicyError('group map must be an object')
    return Analysis(*read_snapshot(path), groups=gm)

def _save(text: str, path: str | None) -> None:
    if path:
        Path(path).write_text(text, encoding='utf-8')
    else:
        print(text, end='')

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog='rolepath', description='Offline Kubernetes RBAC entitlement analysis')
    parser.add_argument('--version', action='version', version='rolepath 1.0.0')
    sub = parser.add_subparsers(dest='command', required=True)
    scan = sub.add_parser('scan', help='Analyze binding risks and output JSON/text/SARIF')
    scan.add_argument('--snapshot', required=True)
    scan.add_argument('--format', choices=('text', 'json', 'sarif'), default='text')
    scan.add_argument('--output')
    scan.add_argument('--fail-on', choices=('none', 'low', 'medium', 'high', 'critical'), default='high')
    sim = sub.add_parser('can-i', help='Explain permissions of a named identity')
    sim.add_argument('--snapshot', required=True)
    sim.add_argument('--groups', help='Explicit principal-to-groups JSON map')
    sim.add_argument('--principal', required=True)
    sim.add_argument('--verb', required=True)
    sim.add_argument('--resource', default='')
    sim.add_argument('--api-group', default='')
    sim.add_argument('--namespace')
    sim.add_argument('--name', help='resourceName query')
    sim.add_argument('--name-filter', action='store_true', help='list/watch metadata.name selector supplied')
    sim.add_argument('--non-resource-url')
    sim.add_argument('--output')
    diff = sub.add_parser('diff', help='Compare decisions over an explicit query matrix')
    diff.add_argument('--baseline', required=True)
    diff.add_argument('--candidate', required=True)
    diff.add_argument('--queries', required=True)
    diff.add_argument('--groups')
    diff.add_argument('--output')
    diff.add_argument('--fail-on-expansion', action='store_true')
    check = sub.add_parser('assert', help='Check explicit expected allow/deny invariant')
    check.add_argument('--snapshot', required=True)
    check.add_argument('--checks', required=True)
    check.add_argument('--groups')
    check.add_argument('--output')
    return parser

def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.command == 'scan':
            findings = _analysis(args.snapshot).scan()
            _save(render(findings, args.format), args.output)
            return int(args.fail_on != 'none' and any(SEVERITIES[f['severity']] >= SEVERITIES[args.fail_on] for f in findings))
        if args.command == 'can-i':
            q = Request(args.principal, args.verb, args.resource, args.api_group,
                        args.namespace, args.name, args.non_resource_url, args.name_filter)
            result = _analysis(args.snapshot, args.groups).explain(q)
            _save(render(result, 'json'), args.output)
            return 0 if result['allowed'] else 1
        if args.command == 'diff':
            raw = _load_json(args.queries)
            if not isinstance(raw, list):
                raise PolicyError('queries must be an array')
            result = compare(_analysis(args.baseline, args.groups), _analysis(args.candidate, args.groups),
                             [Request.from_dict(q) for q in raw])
            _save(render(result, 'json'), args.output)
            return int(args.fail_on_expansion and result['expansions'] > 0)
        raw = _load_json(args.checks)
        if not isinstance(raw, list) or len(raw) > 10_000:
            raise PolicyError('checks must be an array of at most 10,000 entries')
        analyst = _analysis(args.snapshot, args.groups)
        results = []
        for entry in raw:
            if not isinstance(entry, dict) or not isinstance(entry.get('allowed'), bool):
                raise PolicyError('each check requires boolean allowed')
            q = Request.from_dict({k: v for k, v in entry.items() if k != 'allowed'})
            actual = bool(analyst.decide(q))
            results.append({'request': vars(q), 'expected': entry['allowed'], 'actual': actual,
                            'passed': actual == entry['allowed']})
        result = {'checked': len(results), 'failures': sum(not x['passed'] for x in results), 'results': results}
        _save(render(result, 'json'), args.output)
        return int(result['failures'] > 0)
    except (PolicyError, OSError) as exc:
        print(f'rolepath: {exc}', file=sys.stderr)
        return 2

if __name__ == '__main__':
    raise SystemExit(main())
