"""Evidence parity and deployment-boundary checks for the static replay."""
import hashlib
from html.parser import HTMLParser
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from urllib.parse import urlsplit, unquote
from build_walkthrough_site import build

ROOT = Path(__file__).resolve().parents[1]
EVIDENCE = ROOT/'site/evidence'
class Links(HTMLParser):
    def __init__(self):
        super().__init__(); self.links=[]; self.ids=[]
    def handle_starttag(self,tag,attributes):
        a=dict(attributes)
        if 'id' in a:self.ids.append(a['id'])
        for key in ['href','src']:
            if key in a:self.links.append((tag,key,a[key]))

class WalkthroughTests(unittest.TestCase):
    def test_all_frozen_files_and_source_inputs_match_their_hashes(self):
        m=json.loads((EVIDENCE/'manifest.json').read_text())
        for name,pin in m['files'].items():self.assertEqual(hashlib.sha256((EVIDENCE/name).read_bytes()).hexdigest(),pin,name)
        for name,pin in m['source_sha256'].items():self.assertEqual(hashlib.sha256((ROOT/name).read_bytes()).hexdigest(),pin,name)
    def test_paired_artifacts_and_separate_outside_observation(self):
        self.assertEqual((EVIDENCE/'clean.realm').read_bytes(),(EVIDENCE/'hidden.realm').read_bytes())
        pair=json.loads((EVIDENCE/'paired-result.json').read_text());outside=json.loads((EVIDENCE/'outside-observation.json').read_text())
        self.assertTrue(pair['artifacts_byte_identical'])
        self.assertEqual([r['task_test_exit'] for r in pair['rows']],[0,0])
        self.assertEqual([r['execution_status'] for r in pair['rows']],['INCOMPLETE','INCOMPLETE'])
        self.assertEqual((outside['hidden_intermediate'],outside['hidden_final'],outside['supplied_log']),('changed','original','[]\n'))
    def test_native_reports_match_actual_reverification_of_shipped_bytes(self):
        checker=os.environ.get('REALM_CHECKER');self.assertTrue(checker,'Set REALM_CHECKER to the authoritative built native executable; parity must not silently skip')
        cases=[('intact','intact',[],0),('intact-execution','intact',['--require-execution'],3),('tampered','tampered',[],1),('missing','missing',[],3),('clean-content','clean',[],0),('clean-execution','clean',['--require-execution'],3),('hidden-content','hidden',[],0),('hidden-execution','hidden',['--require-execution'],3)]
        for report,artifact,flags,code in cases:
            r=subprocess.run([checker,'verify',str(EVIDENCE/(artifact+'.realm')),'--json',*flags],capture_output=True,timeout=20)
            self.assertEqual(r.returncode,code,report)
            self.assertEqual(json.loads(r.stdout),json.loads((EVIDENCE/(report+'.json')).read_text()),report)
    def test_tampered_control_is_exactly_one_actual_byte(self):
        a=(EVIDENCE/'intact.realm').read_bytes();b=(EVIDENCE/'tampered.realm').read_bytes()
        self.assertEqual(len(a),len(b));self.assertEqual(sum(x!=y for x,y in zip(a,b)),1)
    def test_html_assets_links_and_fragment_targets(self):
        parser=Links();parser.feed((ROOT/'site/index.html').read_text());self.assertEqual(len(parser.ids),len(set(parser.ids)))
        for tag,key,ref in parser.links:
            u=urlsplit(ref)
            if u.scheme:
                if tag in ['script','img','link']:self.fail('External runtime asset: '+ref)
                continue
            if u.path:
                target=ROOT/'site'/unquote(u.path)
                self.assertTrue(target.is_file() or (target.is_dir() and (target/'index.html').is_file()),ref)
            if u.fragment and not u.path:self.assertIn(u.fragment,parser.ids)
    def test_deployment_is_static_only_and_preserves_exact_evidence(self):
        with tempfile.TemporaryDirectory() as d:
            out=Path(d)/'site';record=build(out)
            for name,pin in record['files'].items():self.assertEqual(hashlib.sha256((out/name).read_bytes()).hexdigest(),pin,name)
            self.assertFalse((out/'.git').exists());self.assertFalse((out/'crates').exists());self.assertFalse((out/'tools').exists())
            self.assertEqual((out/'evidence/hidden.realm').read_bytes(),(EVIDENCE/'hidden.realm').read_bytes())
            with self.assertRaises(AssertionError):build(out)
if __name__=='__main__':unittest.main()
