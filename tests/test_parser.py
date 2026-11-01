import json
import tempfile
import unittest
from pathlib import Path
from rolepath_guard.model import PolicyError
from rolepath_guard.parser import parse_objects, read_snapshot, MAX_BYTES
from common import role, bind

class ParserTests(unittest.TestCase):
    def test_valid_role(self):
        r,b = parse_objects([role()]); self.assertEqual(len(r),1); self.assertFalse(b)
    def test_yaml_multidoc(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/'demo.yaml'
            p.write_text('---\n'+json.dumps(role())+'\n---\n'+json.dumps(bind()), encoding='utf-8')
            r,b = read_snapshot(p); self.assertEqual((len(r),len(b)),(1,1))
    def test_json_list(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/'snapshot.json';p.write_text(json.dumps([role(),bind()]),encoding='utf-8')
            r,b=read_snapshot(p);self.assertEqual((len(r),len(b)),(1,1))
    def test_k8s_list(self):
        r,b=parse_objects([{'kind':'List','items':[role(),bind()]}]);self.assertEqual((len(r),len(b)),(1,1))
    def test_null_doc(self):
        r,b=parse_objects([None,role(),None]);self.assertEqual(len(r),1)
    def test_unknown_kind(self):
        with self.assertRaises(PolicyError):parse_objects([{'kind':'Pod','metadata':{'name':'x'}}])
    def test_wrong_version(self):
        obj=role();obj['apiVersion']='v1'
        with self.assertRaises(PolicyError):parse_objects([obj])
    def test_duplicate(self):
        with self.assertRaises(PolicyError):parse_objects([role(),role()])
    def test_no_meta(self):
        obj=role();del obj['metadata']
        with self.assertRaises(PolicyError):parse_objects([obj])
    def test_missing_name(self):
        obj=role();del obj['metadata']['name']
        with self.assertRaises(PolicyError):parse_objects([obj])
    def test_bad_labels(self):
        obj=role();obj['metadata']['labels']={'t':1}
        with self.assertRaises(PolicyError):parse_objects([obj])
    def test_cluster_namespace_rejected(self):
        obj=role(kind='ClusterRole');obj['metadata']['namespace']='apps'
        with self.assertRaises(PolicyError):parse_objects([obj])
    def test_invalid_namespace_zero_rejected(self):
        obj=role(); obj['metadata']['namespace']=0
        with self.assertRaises(PolicyError):parse_objects([obj])
    def test_implicit_default_namespace(self):
        obj=role();del obj['metadata']['namespace']
        roles,_=parse_objects([obj]);self.assertIn(('Role','default','viewer'),roles)
    def test_role_nonresource_denied(self):
        with self.assertRaises(PolicyError):parse_objects([role(rules=[{'verbs':['get'],'nonResourceURLs':['/healthz']}])])
    def test_no_api_groups(self):
        with self.assertRaises(PolicyError):parse_objects([role(rules=[{'verbs':['get'],'resources':['pods']}])])
    def test_empty_verb(self):
        with self.assertRaises(PolicyError):parse_objects([role(rules=[{'verbs':[],'apiGroups':[''],'resources':['pods']}])])
    def test_mixed_resource_url(self):
        with self.assertRaises(PolicyError):parse_objects([role(kind='ClusterRole',rules=[{'verbs':['get'],'apiGroups':[''],'resources':['pods'],'nonResourceURLs':['/healthz']}])])
    def test_invalid_binding_role_ref(self):
        obj=bind();obj['roleRef']['apiGroup']='invalid'
        with self.assertRaises(PolicyError):parse_objects([obj])
    def test_invalid_clusterrolebinding(self):
        with self.assertRaises(PolicyError):parse_objects([bind(kind='ClusterRoleBinding',role_kind='Role')])
    def test_invalid_subject(self):
        with self.assertRaises(PolicyError):parse_objects([bind(subjects=[{'kind':'Unknown','name':'x'}])])
    def test_invalid_group_subject_api(self):
        with self.assertRaises(PolicyError):parse_objects([bind(subjects=[{'kind':'Group','name':'g'}])])
    def test_serviceaccount_namespace_default(self):
        _,bs=parse_objects([bind(subjects=[{'kind':'ServiceAccount','name':'bot'}])])
        self.assertEqual(bs[0].subjects[0].identity,'ServiceAccount:apps:bot')
    def test_cluster_sa_namespace_required(self):
        with self.assertRaises(PolicyError):parse_objects([bind(kind='ClusterRoleBinding',role_kind='ClusterRole',subjects=[{'kind':'ServiceAccount','name':'bot'}])])
    def test_duplicate_yaml_keys_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/'repeat.yaml'
            p.write_text('kind: Role\nkind: RoleBinding\n',encoding='utf-8')
            with self.assertRaises(PolicyError):read_snapshot(p)
    def test_duplicate_json_keys_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/'repeat.json'
            p.write_text('{"kind":"Role","kind":"ClusterRole"}',encoding='utf-8')
            with self.assertRaises(PolicyError):read_snapshot(p)
    def test_oversized_input(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/'big.yaml';p.write_bytes(b'a'*(MAX_BYTES+1))
            with self.assertRaises(PolicyError):read_snapshot(p)
    def test_oversized_objects(self):
        with self.assertRaises(PolicyError):parse_objects([{'kind':'List','items':[None]*10001}])
    def test_no_file(self):
        with self.assertRaises(PolicyError):read_snapshot('/nonexistent/demo.yml')
    def test_syntax_error(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/'bad.json';p.write_text('{',encoding='utf-8')
            with self.assertRaises(PolicyError):read_snapshot(p)
    def test_bad_aggregation(self):
        obj=role(kind='ClusterRole');obj['aggregationRule']={'clusterRoleSelectors':'bad'}
        with self.assertRaises(PolicyError):parse_objects([obj])
