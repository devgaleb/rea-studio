import json, unittest, sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from android_analysis import analyze_jadx_tree
HERE=Path(__file__).resolve().parent
class ProviderOutputTests(unittest.TestCase):
 def test_ghidra_export_schema_has_graph_and_evidence(self):
  d=json.loads((HERE/'fixtures/ghidra-output.json').read_text()); f=d['functions'][0]
  self.assertEqual(d['provider'],'Ghidra'); self.assertTrue(f['entry']); self.assertTrue(f['instructions'][0]['address']); self.assertEqual(f['basicBlocks'][0]['successors'],['00401005'])
 def test_ida_export_schema_has_graph_and_incoming_xrefs(self):
  d=json.loads((HERE/'fixtures/ida-output.json').read_text()); f=d['functions'][0]
  self.assertEqual(d['provider'],'IDA'); self.assertEqual(f['xrefs'][0]['from'],'0x402000'); self.assertEqual(len(f['basicBlocks']),2); self.assertEqual(f['calls'][0]['name'],'sub_401100')
 def test_jadx_manifest_permissions_components_and_calls(self):
  d=analyze_jadx_tree(HERE/'fixtures/jadx-out')
  self.assertIn('android.permission.READ_CONTACTS',d['permissions']); self.assertEqual({x['type'] for x in d['components']},{'activity','service'})
  self.assertTrue(any(x['target']=='query' for x in d['crossReferences'])); self.assertTrue(any(x['permission']=='android.permission.READ_CONTACTS' for x in d['permissionFindings']))
  self.assertEqual(d['summary']['javaFiles'],1)
if __name__=='__main__': unittest.main()
