"""Deterministic machine-readable reports for CI review."""
from __future__ import annotations
import json
from typing import Any

LEVELS = {'critical': 'error', 'high': 'error', 'medium': 'warning', 'low': 'note'}

def sarif(findings: list[dict[str, Any]]) -> dict[str, Any]:
    rules = {f['id']: f for f in findings}
    return {'version': '2.1.0', '$schema': 'https://json.schemastore.org/sarif-2.1.0.json', 'runs': [{
        'tool': {'driver': {'name': 'RolePath Guard', 'version': '1.0.0',
                            'informationUri': 'https://github.com/felipewatter/rolepath-guard',
                            'rules': [{'id': key, 'shortDescription': {'text': value['message']},
                                       'properties': {'security-severity': {'critical': '9.0', 'high': '7.0', 'medium': '5.0', 'low': '2.0'}[value['severity']]}}
                                      for key, value in sorted(rules.items())]}},
        'results': [{'ruleId': f['id'], 'level': LEVELS[f['severity']],
                     'message': {'text': f['message']},
                     'partialFingerprints': {'primaryLocationLineHash': f"{f['binding']}:{f['subject']}:{f['rule_index']}:{f['id']}"},
                     'properties': {k: f[k] for k in ('binding', 'role', 'subject', 'rule_index', 'severity', 'caveat')}}
                    for f in findings]
    }]}

def render(data: Any, fmt: str) -> str:
    if fmt == 'json':
        return json.dumps(data, indent=2, ensure_ascii=False, sort_keys=True) + '\n'
    if fmt == 'sarif':
        return json.dumps(sarif(data), indent=2, ensure_ascii=False, sort_keys=True) + '\n'
    if fmt == 'text':
        if isinstance(data, list):
            return '\n'.join(f"[{f['severity'].upper()}] {f['id']} {f['binding']} {f['subject']}: {f['message']}" for f in data) + ('\n' if data else 'No findings.\n')
        return json.dumps(data, indent=2, ensure_ascii=False, sort_keys=True) + '\n'
    raise ValueError('unknown format')
