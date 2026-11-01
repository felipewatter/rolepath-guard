import unittest
from rolepath_guard.engine import effective_identities, rule_matches, compare, resolve_aggregation
from rolepath_guard.model import PolicyError, Request, Rule
from common import role, bind, analyze

class EngineTests(unittest.TestCase):
    def test_namespaced_access(self):
        a=analyze(role(),bind())
        self.assertTrue(a.decide(Request('User:alice','get','pods',namespace='apps')))
        self.assertFalse(a.decide(Request('User:alice','get','pods',namespace='other')))
    def test_unknown_principal(self):
        a=analyze(role(),bind())
        self.assertFalse(a.decide(Request('User:bob','get','pods',namespace='apps')))
    def test_role_binding_clusterrole_namespaced(self):
        a=analyze(role(kind='ClusterRole'),bind(role_kind='ClusterRole'))
        self.assertTrue(a.decide(Request('User:alice','get','pods',namespace='apps')))
        self.assertFalse(a.decide(Request('User:alice','get','pods',namespace='other')))
    def test_clusterrolebinding_global(self):
        a=analyze(role(kind='ClusterRole'),bind(kind='ClusterRoleBinding',role_kind='ClusterRole'))
        for ns in ('apps','other',None):
            with self.subTest(ns=ns):self.assertTrue(a.decide(Request('User:alice','get','pods',namespace=ns)))
    def test_nonresource_clusterrolebinding_only(self):
        r=role(kind='ClusterRole',rules=[{'verbs':['get'],'nonResourceURLs':['/readyz/*']}])
        a=analyze(r,bind(kind='ClusterRoleBinding',role_kind='ClusterRole'))
        self.assertTrue(a.decide(Request('User:alice','get',non_resource_url='/readyz/healthy')))
        self.assertFalse(a.decide(Request('User:alice','get',non_resource_url='/healthz')))
        b=analyze(r,bind(role_kind='ClusterRole'))
        self.assertFalse(b.decide(Request('User:alice','get',non_resource_url='/readyz/healthy')))
    def test_resource_names_only(self):
        r=role(rules=[{'verbs':['get','list','watch','create','deletecollection'],'apiGroups':[''],'resources':['pods'],'resourceNames':['safe']}])
        a=analyze(r,bind())
        self.assertTrue(a.decide(Request('User:alice','get','pods',namespace='apps',resource_name='safe')))
        self.assertFalse(a.decide(Request('User:alice','get','pods',namespace='apps',resource_name='unsafe')))
        self.assertFalse(a.decide(Request('User:alice','get','pods',namespace='apps')))
        for v in ('create','deletecollection'):
            self.assertFalse(a.decide(Request('User:alice',v,'pods',namespace='apps',resource_name='safe')))
        self.assertFalse(a.decide(Request('User:alice','list','pods',namespace='apps',resource_name='safe')))
        self.assertTrue(a.decide(Request('User:alice','watch','pods',namespace='apps',resource_name='safe',name_filter=True)))
    def test_subresource_glob(self):
        for pattern,target,expected in [('pods/*','pods/exec',True),('*/status','pods/status',True),('pods/*','services/status',False),('*','jobs',True),('pods','pods/exec',False)]:
            with self.subTest(pattern=pattern):
                self.assertEqual(rule_matches(Rule(('create',),('',),(pattern,)),Request('User:alice','create',target)),expected)
    def test_api_group(self):
        r=Rule(('get',),('apps',),('deployments',))
        self.assertTrue(rule_matches(r,Request('User:x','get','deployments','apps')))
        self.assertFalse(rule_matches(r,Request('User:x','get','deployments','')))
    def test_verbs(self):
        self.assertFalse(rule_matches(Rule(('get',),('',),('pods',)),Request('User:alice','delete','pods')))
    def test_wildcard(self):
        self.assertTrue(rule_matches(Rule(('*',),('*',),('*',)),Request('User:alice','delete','secrets','')))
    def test_group_membership(self):
        a=analyze(role(),bind(subjects=[{'kind':'Group','name':'dev','apiGroup':'rbac.authorization.k8s.io'}]),groups={'User:alice':['dev']})
        self.assertTrue(a.decide(Request('User:alice','get','pods',namespace='apps')))
        self.assertFalse(a.decide(Request('User:bob','get','pods',namespace='apps')))
    def test_serviceaccount_group(self):
        ids=effective_identities('ServiceAccount:apps:bot')
        self.assertIn('Group:system:serviceaccounts:apps',ids)
        self.assertNotIn('Group:system:serviceaccounts:other',ids)
    def test_serviceaccount_username_equivalence(self):
        a=analyze(role(),bind(subjects=[{'kind':'ServiceAccount','name':'bot','namespace':'apps'}]))
        self.assertTrue(a.decide(Request('User:system:serviceaccount:apps:bot','get','pods',namespace='apps')))
        self.assertTrue(a.decide(Request('ServiceAccount:apps:bot','get','pods',namespace='apps')))
    def test_authenticated_group(self):
        self.assertIn('Group:system:authenticated',effective_identities('User:alice'))
    def test_anonymous_group(self):
        x=effective_identities('User:system:anonymous')
        self.assertIn('Group:system:unauthenticated',x)
        self.assertNotIn('Group:system:authenticated',x)
    def test_unresolved_role_rejected(self):
        with self.assertRaises(PolicyError):analyze(bind())
    def test_multiple_evidence(self):
        a=analyze(role(),bind(),bind(name='copy'))
        self.assertEqual(len(a.decide(Request('User:alice','get','pods',namespace='apps'))),2)
    def test_aggregation_matchlabels(self):
        agg=role('aggregated',kind='ClusterRole',rules=[],aggregation=[{'matchLabels':{'cat':'safe'}}])
        r=role('part',kind='ClusterRole',labels={'cat':'safe'})
        a=analyze(agg,r,bind('aggregated',kind='ClusterRoleBinding',role_kind='ClusterRole'))
        self.assertTrue(a.decide(Request('User:alice','get','pods',namespace='apps')))
    def test_empty_aggregation_overrides_manual_rules(self):
        a=role('aggregate',kind='ClusterRole',aggregation=[])
        subject=analyze(a,bind('aggregate',kind='ClusterRoleBinding',role_kind='ClusterRole'))
        self.assertFalse(subject.decide(Request('User:alice','get','pods')))
    def test_aggregation_mismatch(self):
        agg=role('aggregated',kind='ClusterRole',rules=[],aggregation=[{'matchLabels':{'cat':'safe'}}])
        r=role('part',kind='ClusterRole',labels={'cat':'unsafe'})
        a=analyze(agg,r,bind('aggregated',kind='ClusterRoleBinding',role_kind='ClusterRole'))
        self.assertFalse(a.decide(Request('User:alice','get','pods',namespace='apps')))
    def test_aggregation_nested(self):
        a=role('a',kind='ClusterRole',rules=[],labels={'tier':'top'},aggregation=[{'matchLabels':{'tier':'middle'}}])
        b=role('b',kind='ClusterRole',rules=[],labels={'tier':'middle'},aggregation=[{'matchLabels':{'tier':'leaf'}}])
        c=role('c',kind='ClusterRole',labels={'tier':'leaf'})
        analyst=analyze(a,b,c,bind('a',kind='ClusterRoleBinding',role_kind='ClusterRole'))
        self.assertTrue(analyst.decide(Request('User:alice','get','pods')))
    def test_aggregation_cycle_terminates(self):
        a=role('a',kind='ClusterRole',rules=[],labels={'tier':'a'},aggregation=[{'matchLabels':{'tier':'b'}}])
        b=role('b',kind='ClusterRole',rules=[],labels={'tier':'b'},aggregation=[{'matchLabels':{'tier':'a'}}])
        analyst=analyze(a,b)
        self.assertFalse(analyst.roles[('ClusterRole',None,'a')].rules)
    def test_aggregation_match_expressions(self):
        agg=role('agg',kind='ClusterRole',rules=[],aggregation=[{'matchExpressions':[{'key':'scope','operator':'In','values':['read']}]}])
        r=role('r',kind='ClusterRole',labels={'scope':'read'})
        a=analyze(agg,r,bind('agg',kind='ClusterRoleBinding',role_kind='ClusterRole'))
        self.assertTrue(a.decide(Request('User:alice','get','pods')))
    def test_aggregation_invalid_operator(self):
        agg=role('agg',kind='ClusterRole',rules=[],aggregation=[{'matchExpressions':[{'key':'x','operator':'bad'}]}])
        r=role('r',kind='ClusterRole',labels={'x':'y'})
        with self.assertRaises(PolicyError):analyze(agg,r)
    def test_diff_new_access(self):
        before=analyze(role(rules=[]),bind())
        after=analyze(role(),bind())
        qs=[Request('User:alice','get','pods',namespace='apps')]
        self.assertEqual(compare(before,after,qs)['expansions'],1)
        self.assertEqual(compare(after,before,qs)['removals'],1)
    def test_diff_same_access(self):
        a=analyze(role(),bind())
        self.assertEqual(compare(a,a,[Request('User:alice','get','pods',namespace='apps')])['changes'],[])
    def test_diff_limit(self):
        a=analyze(role(),bind())
        with self.assertRaises(PolicyError):compare(a,a,[Request('User:alice','get','pods')]*10001)
    def test_risk_wildcard(self):
        a=analyze(role(kind='ClusterRole',rules=[{'apiGroups':['*'],'resources':['*'],'verbs':['*']}]),bind(kind='ClusterRoleBinding',role_kind='ClusterRole'))
        f=a.scan(); self.assertEqual(f[0]['id'],'RPG001');self.assertEqual(f[0]['severity'],'critical')
    def test_risk_secret(self):
        a=analyze(role(rules=[{'apiGroups':[''],'resources':['secrets'],'verbs':['list']}]),bind())
        self.assertEqual(a.scan()[0]['id'],'RPG003')
    def test_risk_pod_exec(self):
        a=analyze(role(rules=[{'apiGroups':[''],'resources':['pods/exec'],'verbs':['create']}]),bind())
        self.assertEqual(a.scan()[0]['id'],'RPG005')
    def test_risk_authenticated(self):
        a=analyze(role(),bind(subjects=[{'kind':'Group','name':'system:authenticated','apiGroup':'rbac.authorization.k8s.io'}]))
        self.assertEqual(a.scan()[0]['id'],'RPG002')
    def test_risk_escalate(self):
        a=analyze(role(rules=[{'apiGroups':['rbac.authorization.k8s.io'],'resources':['roles'],'verbs':['escalate']}]),bind())
        self.assertEqual(a.scan()[0]['id'],'RPG004')
    def test_clean_readonly(self):
        self.assertEqual(analyze(role(),bind()).scan(),[])
    def test_invalid_query_principal(self):
        with self.assertRaises(PolicyError):Request('alice','get','pods')
    def test_invalid_query_no_target(self):
        with self.assertRaises(PolicyError):Request('User:alice','get')
    def test_invalid_query_both_target_types(self):
        with self.assertRaises(PolicyError):Request('User:alice','get','pods',non_resource_url='/a')
    def test_invalid_request_unknown_fields(self):
        with self.assertRaises(PolicyError):Request.from_dict({'principal':'User:alice','verb':'get','resource':'pods','other':2})
