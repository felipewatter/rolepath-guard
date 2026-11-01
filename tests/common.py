from rolepath_guard.engine import Analysis
from rolepath_guard.parser import parse_objects

API = 'rbac.authorization.k8s.io/v1'

def role(name='viewer', *, kind='Role', namespace='apps', rules=None, labels=None, aggregation=None):
    metadata = {'name': name}
    if kind == 'Role': metadata['namespace'] = namespace
    if labels is not None: metadata['labels'] = labels
    out = {'apiVersion': API, 'kind': kind, 'metadata': metadata, 'rules': rules if rules is not None else [
           {'apiGroups': [''], 'resources': ['pods'], 'verbs': ['get']} ]}
    if aggregation is not None: out['aggregationRule'] = {'clusterRoleSelectors': aggregation}
    return out

def bind(role_name='viewer', *, kind='RoleBinding', name='my-binding', namespace='apps', role_kind='Role',
         subjects=None):
    meta = {'name': name}
    if kind == 'RoleBinding': meta['namespace'] = namespace
    return {'apiVersion': API, 'kind': kind, 'metadata': meta,
            'roleRef': {'apiGroup': 'rbac.authorization.k8s.io', 'kind': role_kind, 'name': role_name},
            'subjects': subjects if subjects is not None else [{'kind': 'User', 'name': 'alice', 'apiGroup': 'rbac.authorization.k8s.io'}]}

def analyze(*objects, groups=None):
    return Analysis(*parse_objects(list(objects)), groups=groups)
