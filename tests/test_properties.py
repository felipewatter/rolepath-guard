"""Deterministic randomized checks against a separate elementary permission oracle."""
import random
import unittest
from rolepath_guard.engine import rule_matches
from rolepath_guard.model import Request, Rule, PolicyError
from common import role, bind, analyze

class PropertyTests(unittest.TestCase):
    def test_exact_resource_decisions_differential(self):
        randomizer=random.Random(20261101)
        verbs=['get','list','watch','create','update','patch','delete']
        resources=['pods','secrets','configmaps','deployments','pods/exec']
        groups=['','apps','rbac.authorization.k8s.io']
        for i in range(750):
            policy_verb=randomizer.choice(verbs+['*'])
            policy_res=randomizer.choice(resources+['*'])
            policy_group=randomizer.choice(groups+['*'])
            reqverb=randomizer.choice(verbs)
            reqres=randomizer.choice(resources)
            reqgroup=randomizer.choice(groups)
            expected=((policy_verb=='*' or policy_verb==reqverb)
                      and (policy_res=='*' or policy_res==reqres)
                      and (policy_group=='*' or policy_group==reqgroup))
            with self.subTest(case=i):
                actual=rule_matches(Rule((policy_verb,),(policy_group,),(policy_res,)),
                                    Request('User:tester',reqverb,reqres,reqgroup))
                self.assertEqual(actual, expected)

    def test_scopes_differential(self):
        rnd=random.Random(321)
        for i in range(300):
            ns=rnd.choice(['apps','monitoring','db'])
            target=rnd.choice(['apps','monitoring','db',None])
            cluster=rnd.choice((True,False))
            rk='ClusterRole' if cluster else 'Role'
            bk='ClusterRoleBinding' if cluster else 'RoleBinding'
            source=role(kind=rk,namespace=ns)
            binding=bind(kind=bk,role_kind=rk,namespace=ns)
            analyst=analyze(source,binding)
            with self.subTest(case=i):
                self.assertEqual(bool(analyst.decide(Request('User:alice','get','pods',namespace=target))),cluster or target==ns)

    def test_rule_names_differential(self):
        rnd=random.Random(456)
        for i in range(300):
            allowedname=rnd.choice(['pod-a','pod-b','pod-c'])
            requested=rnd.choice(['pod-a','pod-b','pod-c',None])
            verb=rnd.choice(['get','create','list','watch','deletecollection'])
            filter_state=rnd.choice((True,False))
            rule=Rule((verb,),('',),('pods',),(allowedname,))
            expected=(requested==allowedname and verb not in ('create','deletecollection')
                      and (verb not in ('list','watch') or filter_state))
            with self.subTest(case=i):
                self.assertEqual(rule_matches(rule,Request('User:alice',verb,'pods',resource_name=requested,name_filter=filter_state)),expected)

    def test_validation_rejects_service_account_without_namespace(self):
        with self.assertRaises(PolicyError):Request('ServiceAccount:foo','get','pods')

    def test_explicit_namespaced_rolebinding_clusterrole_not_global(self):
        r=role(kind='ClusterRole')
        b=bind(role_kind='ClusterRole')
        a=analyze(r,b)
        self.assertFalse(a.decide(Request('User:alice','get','pods',namespace=None)))
        self.assertTrue(a.decide(Request('User:alice','get','pods',namespace='apps')))
