import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path
from rolepath_guard.cli import main
from rolepath_guard.report import sarif,render

BASE = Path(__file__).resolve().parents[1] / 'examples'

class CliTests(unittest.TestCase):
    def invoke(self,*argv):
        stdout,stderr=io.StringIO(),io.StringIO()
        with contextlib.redirect_stdout(stdout),contextlib.redirect_stderr(stderr):
            code=main(list(argv))
        return code,stdout.getvalue(),stderr.getvalue()
    def test_scan_clean(self):
        rc,out,_=self.invoke('scan','--snapshot',str(BASE/'baseline.yaml'))
        self.assertEqual(rc,0);self.assertIn('No findings',out)
    def test_scan_risky(self):
        rc,out,_=self.invoke('scan','--snapshot',str(BASE/'candidate.yaml'),'--format','json','--fail-on','high')
        self.assertEqual(rc,1);self.assertTrue(json.loads(out))
    def test_scan_warn_threshold(self):
        rc,_,_=self.invoke('scan','--snapshot',str(BASE/'candidate.yaml'),'--fail-on','critical')
        self.assertEqual(rc,0)
    def test_scan_sarif(self):
        rc,out,_=self.invoke('scan','--snapshot',str(BASE/'candidate.yaml'),'--format','sarif','--fail-on','none')
        self.assertEqual(rc,0);self.assertEqual(json.loads(out)['version'],'2.1.0')
    def test_can_i_allow(self):
        rc,out,_=self.invoke('can-i','--snapshot',str(BASE/'baseline.yaml'),'--groups',str(BASE/'groups.json'),
                             '--principal','User:alice@example.test','--verb','get','--resource','configmaps','--namespace','apps')
        self.assertEqual(rc,0);self.assertTrue(json.loads(out)['allowed'])
    def test_can_i_deny(self):
        rc,out,_=self.invoke('can-i','--snapshot',str(BASE/'baseline.yaml'),'--groups',str(BASE/'groups.json'),
                             '--principal','User:alice@example.test','--verb','get','--resource','secrets','--namespace','apps')
        self.assertEqual(rc,1);self.assertFalse(json.loads(out)['allowed'])
    def test_diff_expands(self):
        rc,out,_=self.invoke('diff','--baseline',str(BASE/'baseline.yaml'),'--candidate',str(BASE/'candidate.yaml'),
                             '--groups',str(BASE/'groups.json'),'--queries',str(BASE/'queries.json'),'--fail-on-expansion')
        self.assertEqual(rc,1); self.assertEqual(json.loads(out)['expansions'],1)
    def test_diff_reverse(self):
        rc,out,_=self.invoke('diff','--baseline',str(BASE/'candidate.yaml'),'--candidate',str(BASE/'baseline.yaml'),
                             '--groups',str(BASE/'groups.json'),'--queries',str(BASE/'queries.json'),'--fail-on-expansion')
        self.assertEqual(rc,0); self.assertEqual(json.loads(out)['removals'],1)
    def test_assert_pass(self):
        rc,out,_=self.invoke('assert','--snapshot',str(BASE/'baseline.yaml'),'--groups',str(BASE/'groups.json'),'--checks',str(BASE/'invariants.json'))
        self.assertEqual(rc,0);self.assertEqual(json.loads(out)['failures'],0)
    def test_assert_fail(self):
        checks=[{'principal':'User:alice','verb':'get','resource':'pods','allowed':True}]
        with tempfile.TemporaryDirectory() as d:
            f=Path(d)/'check.json';f.write_text(json.dumps(checks))
            rc,out,_=self.invoke('assert','--snapshot',str(BASE/'baseline.yaml'),'--checks',str(f))
        self.assertEqual(rc,1);self.assertEqual(json.loads(out)['failures'],1)
    def test_invalid_snapshot_exit2(self):
        rc,out,err=self.invoke('scan','--snapshot','/not/a/file')
        self.assertEqual(rc,2);self.assertIn('file not found',err)
    def test_output_file(self):
        with tempfile.TemporaryDirectory() as d:
            f=Path(d)/'result.json'
            rc,stdout,_=self.invoke('scan','--snapshot',str(BASE/'baseline.yaml'),'--format','json','--output',str(f))
            self.assertEqual(rc,0);self.assertEqual(stdout,'');self.assertEqual(json.loads(f.read_text()),[])
    def test_sarif_rules_stable(self):
        findings=[{'id':'RPG003','severity':'high','message':'secret access','binding':'RB','role':'R', 'subject':'User:test', 'rule_index':0,'caveat':'heuristic'}]
        result=sarif(findings)
        self.assertEqual(result['runs'][0]['results'][0]['ruleId'],'RPG003')
    def test_text_report_empty(self):
        self.assertEqual(render([],'text'),'No findings.\n')
