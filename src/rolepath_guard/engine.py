"""Pure, deterministic RBAC evaluator; no cluster, shell or network access."""
from __future__ import annotations
from dataclasses import dataclass, replace
from typing import Any
from .model import Binding, Evidence, PolicyError, Request, Role, Rule


def _selector_matches(selector: dict[str, Any], labels: dict[str, str]) -> bool:
    if set(selector) - {'matchLabels', 'matchExpressions'}:
        raise PolicyError('unsupported label selector fields')
    match_labels = selector.get('matchLabels', {})
    expressions = selector.get('matchExpressions', [])
    if not isinstance(match_labels, dict) or not isinstance(expressions, list):
        raise PolicyError('invalid label selector')
    if any(not isinstance(k, str) or not isinstance(v, str) for k, v in match_labels.items()):
        raise PolicyError('matchLabels must contain string keys and values')
    if not all(labels.get(k) == v for k, v in match_labels.items()):
        return False
    for item in expressions:
        if not isinstance(item, dict) or not isinstance(item.get('key'), str):
            raise PolicyError('invalid matchExpressions entry')
        key, op, values = item.get('key'), item.get('operator'), item.get('values', [])
        if not isinstance(values, list) or any(not isinstance(x, str) for x in values):
            raise PolicyError('matchExpressions.values must be an array of strings')
        if op == 'In':
            passed = key in labels and labels[key] in values
        elif op == 'NotIn':
            passed = key not in labels or labels[key] not in values
        elif op == 'Exists':
            passed = key in labels
        elif op == 'DoesNotExist':
            passed = key not in labels
        else:
            raise PolicyError(f'unsupported label selector operator {op}')
        if not passed:
            return False
    return True


def resolve_aggregation(roles: dict[tuple, Role]) -> dict[tuple, Role]:
    """Compute controller-style ClusterRole aggregation to a least fixed point."""
    resolved = dict(roles)
    aggregators = [key for key, role in resolved.items() if role.aggregation_defined]
    for key in aggregators:
        resolved[key] = replace(resolved[key], rules=())
    for _ in range(len(aggregators) + 1):
        changed = False
        for key in sorted(aggregators):
            original = roles[key]
            combined = []
            for other_key in sorted(resolved):
                other = resolved[other_key]
                if other.kind != 'ClusterRole' or other_key == key:
                    continue
                labels = dict(other.labels)
                if any(_selector_matches(sel, labels) for sel in original.selectors):
                    combined.extend(other.rules)
            # Deduplicate while keeping deterministic order. Bound aggregate memory.
            if len(combined) > 100_000:
                raise PolicyError('aggregation exceeds 100,000 intermediate rules')
            deduped = tuple(dict.fromkeys(combined))
            if resolved[key].rules != deduped:
                resolved[key] = replace(resolved[key], rules=deduped)
                changed = True
        if not changed:
            return resolved
    raise PolicyError('aggregation did not reach a fixed point')


def _resource_pattern_matches(pattern: str, requested: str) -> bool:
    if pattern == '*' or pattern == requested:
        return True
    # Kubernetes resource and subresource patterns: pods/* and */status.
    if pattern.endswith('/*') and requested.startswith(pattern[:-1]):
        return True
    if pattern.startswith('*/') and requested.endswith(pattern[1:]):
        return True
    return False


def _url_matches(pattern: str, requested: str) -> bool:
    return pattern == '*' or pattern == requested or (pattern.endswith('/*') and requested.startswith(pattern[:-1]))


def rule_matches(rule: Rule, query: Request) -> bool:
    if query.verb not in rule.verbs and '*' not in rule.verbs:
        return False
    if query.non_resource_url:
        return any(_url_matches(p, query.non_resource_url) for p in rule.non_resource_urls)
    if rule.non_resource_urls:
        return False
    if query.api_group not in rule.api_groups and '*' not in rule.api_groups:
        return False
    if not any(_resource_pattern_matches(p, query.resource) for p in rule.resources):
        return False
    if rule.resource_names:
        # Kubernetes cannot constrain create/deletecollection by resource name.
        if query.verb in ('create', 'deletecollection'):
            return False
        if not query.resource_name or query.resource_name not in rule.resource_names:
            return False
        # Kubernetes list/watch with resourceNames require metadata.name field selector.
        if query.verb in ('list', 'watch') and not query.name_filter:
            return False
    return True


def effective_identities(principal: str, group_map: dict[str, list[str]] | None = None) -> set[str]:
    identities = {principal}
    if principal.startswith('ServiceAccount:'):
        _, ns, name = principal.split(':')
        identities.update((f'User:system:serviceaccount:{ns}:{name}', 'Group:system:serviceaccounts',
                           f'Group:system:serviceaccounts:{ns}', 'Group:system:authenticated'))
    elif principal.startswith('User:system:serviceaccount:') and len(principal.split(':')) == 5:
        _, _, _, ns, name = principal.split(':')
        identities.update((f'ServiceAccount:{ns}:{name}', 'Group:system:serviceaccounts',
                           f'Group:system:serviceaccounts:{ns}', 'Group:system:authenticated'))
    elif principal.startswith('User:'):
        user = principal[5:]
        if user != 'system:anonymous':
            identities.add('Group:system:authenticated')
        else:
            identities.add('Group:system:unauthenticated')
    if group_map:
        for group in group_map.get(principal, []):
            if not isinstance(group, str):
                raise PolicyError('groups must contain strings')
            identities.add(f'Group:{group}')
    return identities


@dataclass
class Analysis:
    roles: dict[tuple, Role]
    bindings: tuple[Binding, ...]
    groups: dict[str, list[str]] | None = None

    def __post_init__(self) -> None:
        self.roles = resolve_aggregation(self.roles)
        if self.groups:
            for principal, groupnames in self.groups.items():
                if not isinstance(principal, str) or not isinstance(groupnames, list):
                    raise PolicyError('group map must be a principal-to-list object')
        # Unresolved bindings are a definite gap and must not be silently dropped.
        for binding in self.bindings:
            key = (binding.role_kind, binding.namespace if binding.role_kind == 'Role' else None, binding.role_name)
            if key not in self.roles:
                raise PolicyError(f'unresolved roleRef {binding.identifier}: {key}')

    def decide(self, query: Request) -> list[Evidence]:
        subjects = effective_identities(query.principal, self.groups)
        found = []
        for binding in self.bindings:
            if binding.kind == 'RoleBinding':
                if query.non_resource_url or binding.namespace != query.namespace:
                    continue
            if binding.kind == 'ClusterRoleBinding' and binding.role_kind != 'ClusterRole':
                continue
            matched = sorted(subjects & {s.identity for s in binding.subjects})
            if not matched:
                continue
            key = (binding.role_kind, binding.namespace if binding.role_kind == 'Role' else None, binding.role_name)
            role = self.roles[key]
            for index, rule in enumerate(role.rules):
                if rule_matches(rule, query):
                    for subject in matched:
                        found.append(Evidence(binding.identifier, f'{role.kind}/{role.namespace or "cluster"}/{role.name}', index, subject))
        return sorted(found, key=lambda x: (x.binding, x.role, x.rule_index, x.subject))

    def explain(self, query: Request) -> dict[str, Any]:
        evidence = [e.to_dict() for e in self.decide(query)]
        return {'request': vars(query), 'allowed': bool(evidence), 'evidence': evidence,
                'scope': 'supplied manifests only; no cluster defaults or admission control'}

    def scan(self) -> list[dict[str, Any]]:
        findings = []
        for binding in self.bindings:
            key = (binding.role_kind, binding.namespace if binding.role_kind == 'Role' else None, binding.role_name)
            role = self.roles[key]
            for subject in binding.subjects:
                for i, rule in enumerate(role.rules):
                    code, level, reason = classify(rule, binding, subject.identity)
                    if code:
                        findings.append({
                            'id': code, 'severity': level, 'message': reason,
                            'binding': binding.identifier, 'role': f'{role.kind}/{role.namespace or "cluster"}/{role.name}',
                            'subject': subject.identity, 'rule_index': i,
                            'caveat': 'Heuristic configuration risk, not proof of exploitable access.'})
        return sorted(findings, key=lambda x: (x['binding'], x['subject'], x['rule_index'], x['id']))


def classify(rule: Rule, binding: Binding, principal: str) -> tuple[str, str, str]:
    verbs = set(rule.verbs)
    resources = set(rule.resources)
    groups = set(rule.api_groups)
    cluster = binding.kind == 'ClusterRoleBinding'
    if ('*' in verbs and '*' in resources and '*' in groups):
        return 'RPG001', 'critical' if cluster else 'high', 'Broad wildcard permission on all verbs, resources and API groups.'
    if principal in ('Group:system:authenticated', 'Group:system:unauthenticated', 'User:system:anonymous'):
        return 'RPG002', 'critical' if cluster else 'high', 'Broad audience binding; review public or authenticated-group access.'
    if ('*' in verbs or verbs & {'get', 'list', 'watch'}) and ('*' in resources or 'secrets' in resources):
        return 'RPG003', 'critical' if cluster else 'high', 'Permissions may allow reading Kubernetes Secrets.'
    if ('*' in verbs or verbs & {'escalate', 'bind', 'impersonate'}) and (resources & {'*', 'roles', 'clusterroles', 'rolebindings', 'clusterrolebindings', 'users', 'groups', 'serviceaccounts'}):
        return 'RPG004', 'high', 'RBAC delegation or identity impersonation permission.'
    if ('*' in verbs or 'create' in verbs) and (resources & {'pods/exec', 'pods/attach', '*'}):
        return 'RPG005', 'high', 'Permission can permit remote execution in containers.'
    if ('*' in verbs or 'create' in verbs) and (resources & {'pods', 'deployments', 'daemonsets', 'jobs', 'cronjobs'}):
        return 'RPG006', 'medium', 'Workload creation merits review for service-account privileges.'
    if ('*' in verbs or 'get' in verbs) and ('*' in rule.non_resource_urls):
        return 'RPG007', 'medium', 'Non-resource URL wildcard.'
    return '', '', ''


def compare(baseline: Analysis, candidate: Analysis, queries: list[Request]) -> dict[str, Any]:
    if len(queries) > 10_000:
        raise PolicyError('query matrix exceeds 10,000 entries')
    results = []
    for query in queries:
        old = baseline.decide(query)
        new = candidate.decide(query)
        if bool(old) != bool(new):
            results.append({'change': 'expanded' if new else 'removed', 'request': vars(query),
                            'before': [e.to_dict() for e in old], 'after': [e.to_dict() for e in new]})
    return {'compared': len(queries), 'changes': results,
            'expansions': sum(item['change'] == 'expanded' for item in results),
            'removals': sum(item['change'] == 'removed' for item in results),
            'limitations': 'Exact only for the supplied query matrix; no exhaustive privilege proof.'}
