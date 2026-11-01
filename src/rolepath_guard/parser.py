"""Strict local-only manifest parser with bounded input and predictable errors."""
from __future__ import annotations
import json
from pathlib import Path
from typing import Any
import yaml
from .model import PolicyError, Rule, Role, Binding, Subject

MAX_BYTES = 2_097_152
MAX_OBJECTS = 10_000
MAX_RULES = 30_000
SUPPORTED = {'Role', 'ClusterRole', 'RoleBinding', 'ClusterRoleBinding'}
MAX_YAML_NODES = 50_000

class StrictLoader(yaml.SafeLoader):
    """SafeLoader additionally rejecting repeated keys and excessive YAML nodes."""
    def compose_node(self, parent: Any, index: Any) -> Any:
        self._visited_nodes = getattr(self, '_visited_nodes', 0) + 1
        if self._visited_nodes > MAX_YAML_NODES:
            raise PolicyError('YAML node count limit exceeded')
        return super().compose_node(parent, index)

    def construct_mapping(self, node: Any, deep: bool = False) -> dict:
        self.flatten_mapping(node)
        seen = set()
        for key_node, _ in node.value:
            key = self.construct_object(key_node, deep=deep)
            try:
                if key in seen:
                    raise PolicyError(f'duplicate YAML key: {key}')
                seen.add(key)
            except TypeError as exc:
                raise PolicyError('unhashable YAML mapping key') from exc
        return super().construct_mapping(node, deep=deep)

def _unique_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result = {}
    for key, value in pairs:
        if key in result:
            raise PolicyError(f'duplicate JSON key: {key}')
        result[key] = value
    return result

def _text(value: Any, context: str, *, allow_empty: bool = False) -> str:
    if not isinstance(value, str) or (not allow_empty and not value.strip()):
        raise PolicyError(f'{context} must be a nonempty string')
    if len(value) > 2048:
        raise PolicyError(f'{context} exceeds length limit')
    return value

def _strings(raw: Any, context: str, *, empty_ok: bool = False) -> tuple[str, ...]:
    if raw is None:
        raw = []
    if not isinstance(raw, list) or len(raw) > 1000:
        raise PolicyError(f'{context} must be a list of at most 1000 strings')
    return tuple(_text(v, context, allow_empty=empty_ok) for v in raw)

def _metadata(obj: dict[str, Any], kind: str) -> tuple[str, str | None, dict[str, str]]:
    meta = obj.get('metadata')
    if not isinstance(meta, dict):
        raise PolicyError(f'{kind} requires metadata object')
    name = _text(meta.get('name'), 'metadata.name')
    namespace = meta.get('namespace')
    if kind in ('Role', 'RoleBinding'):
        namespace = _text('default' if namespace is None else namespace, 'metadata.namespace')
    elif namespace is not None:
        raise PolicyError(f'{kind} is cluster-scoped and must not specify namespace')
    labels = meta.get('labels') or {}
    if not isinstance(labels, dict) or len(labels) > 100:
        raise PolicyError('metadata.labels must be a small object')
    for k, v in labels.items():
        _text(k, 'label key'); _text(v, 'label value', allow_empty=True)
    return name, namespace, labels

def _rules(raw: Any, kind: str) -> tuple[Rule, ...]:
    if not isinstance(raw, list) or len(raw) > 2000:
        raise PolicyError(f'{kind}.rules must be a list (max 2000)')
    result = []
    for item in raw:
        if not isinstance(item, dict):
            raise PolicyError('rule must be an object')
        verbs = _strings(item.get('verbs'), 'verbs')
        resources = _strings(item.get('resources'), 'resources')
        urls = _strings(item.get('nonResourceURLs'), 'nonResourceURLs')
        groups = _strings(item.get('apiGroups'), 'apiGroups', empty_ok=True)
        names = _strings(item.get('resourceNames'), 'resourceNames')
        if not verbs or bool(resources) == bool(urls):
            raise PolicyError('rule requires verbs and exactly one of resources or nonResourceURLs')
        if urls:
            if kind != 'ClusterRole':
                raise PolicyError('nonResourceURLs only supported in ClusterRole')
            if groups or names:
                raise PolicyError('non-resource rules cannot define apiGroups or resourceNames')
            for url in urls:
                if not url.startswith('/') and url != '*':
                    raise PolicyError('nonResourceURLs entries require leading / or *')
        elif not groups:
            raise PolicyError('resource rules require apiGroups; use [""] for core API')
        result.append(Rule(verbs, groups, resources, names, urls))
    return tuple(result)

def parse_objects(documents: list[Any]) -> tuple[dict[tuple[str, str | None, str], Role], tuple[Binding, ...]]:
    flattened = []
    for obj in documents:
        if obj is None:
            continue
        if not isinstance(obj, dict):
            raise PolicyError('top-level YAML documents must be objects')
        if obj.get('kind') == 'List':
            items = obj.get('items')
            if not isinstance(items, list):
                raise PolicyError('List.items must be an array')
            flattened.extend(items)
        else:
            flattened.append(obj)
    if len(flattened) > MAX_OBJECTS:
        raise PolicyError(f'too many RBAC objects (>{MAX_OBJECTS})')
    roles = {}
    bindings = []
    seen = set()
    n_rules = 0
    for obj in flattened:
        if not isinstance(obj, dict):
            raise PolicyError('RBAC item must be an object')
        kind = obj.get('kind')
        if kind not in SUPPORTED:
            raise PolicyError(f'unsupported kind {kind!r}; provide only RBAC resources')
        if obj.get('apiVersion') != 'rbac.authorization.k8s.io/v1':
            raise PolicyError(f'{kind} requires rbac.authorization.k8s.io/v1')
        name, namespace, labels = _metadata(obj, kind)
        key = (kind, namespace, name)
        if key in seen:
            raise PolicyError(f'duplicate RBAC object {key}')
        seen.add(key)
        if kind in ('Role', 'ClusterRole'):
            selectors = ()
            agg = obj.get('aggregationRule')
            if agg is not None:
                if kind != 'ClusterRole' or not isinstance(agg, dict):
                    raise PolicyError('aggregationRule must belong to ClusterRole')
                raw_selectors = agg.get('clusterRoleSelectors')
                if not isinstance(raw_selectors, list) or len(raw_selectors) > 100:
                    raise PolicyError('clusterRoleSelectors must be a list (max 100)')
                if any(not isinstance(s, dict) for s in raw_selectors):
                    raise PolicyError('clusterRoleSelectors entries must be objects')
                selectors = tuple(raw_selectors)
            rules = _rules(obj.get('rules', []), kind)
            n_rules += len(rules)
            roles[key] = Role(kind, name, namespace, rules, tuple(sorted(labels.items())), selectors, agg is not None)
        else:
            ref = obj.get('roleRef')
            if not isinstance(ref, dict) or ref.get('apiGroup') != 'rbac.authorization.k8s.io':
                raise PolicyError('roleRef.apiGroup must be rbac.authorization.k8s.io')
            role_kind = ref.get('kind')
            if role_kind not in ('Role', 'ClusterRole') or (kind == 'ClusterRoleBinding' and role_kind != 'ClusterRole'):
                raise PolicyError('invalid roleRef kind for binding')
            role_name = _text(ref.get('name'), 'roleRef.name')
            raw_subjects = obj.get('subjects', [])
            if not isinstance(raw_subjects, list) or len(raw_subjects) > 1000:
                raise PolicyError('subjects must be a list (max 1000)')
            subjects = []
            for entry in raw_subjects:
                if not isinstance(entry, dict) or entry.get('kind') not in ('User', 'Group', 'ServiceAccount'):
                    raise PolicyError('subject kind must be User, Group, or ServiceAccount')
                skind = entry['kind']
                sname = _text(entry.get('name'), 'subject.name')
                sns = None
                if skind == 'ServiceAccount':
                    sns = namespace if entry.get('namespace') is None else entry.get('namespace')
                    sns = _text(sns, 'subject.namespace')
                if skind in ('User', 'Group') and entry.get('apiGroup') != 'rbac.authorization.k8s.io':
                    raise PolicyError('User/Group subject apiGroup must be rbac.authorization.k8s.io')
                subjects.append(Subject(skind, sname, sns))
            bindings.append(Binding(kind, name, namespace, role_kind, role_name, tuple(subjects)))
    if n_rules > MAX_RULES:
        raise PolicyError('too many rules')
    return roles, tuple(bindings)

def read_snapshot(path: str | Path) -> tuple[dict, tuple]:
    source = Path(path)
    if not source.is_file():
        raise PolicyError(f'file not found: {source}')
    if source.stat().st_size > MAX_BYTES:
        raise PolicyError('snapshot exceeds 2 MiB limit')
    try:
        payload = source.read_text(encoding='utf-8-sig')
        if source.suffix.lower() == '.json':
            parsed = json.loads(payload, object_pairs_hook=_unique_pairs)
            docs = parsed if isinstance(parsed, list) else [parsed]
        else:
            docs = []
            for doc in yaml.load_all(payload, Loader=StrictLoader):
                docs.append(doc)
                if len(docs) > MAX_OBJECTS:
                    raise PolicyError('too many YAML documents')
    except (UnicodeError, yaml.YAMLError, json.JSONDecodeError) as e:
        raise PolicyError(f'invalid snapshot: {e}') from e
    return parse_objects(docs)
