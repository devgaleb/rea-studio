"""Opt-in validation against outputs exported by installed Ghidra/IDA/JADX.

Set REA_GHIDRA_TEST_JSON, REA_IDA_TEST_JSON and/or REA_JADX_TEST_DIR to paths
created by real provider runs. CI uses deterministic captured-schema fixtures in
addition to these optional tests.
"""
import json, os, sys, unittest
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from android_analysis import analyze_jadx_tree

class LiveProviderOutputTests(unittest.TestCase):
 def validate_functions(self, path, provider):
  data=json.loads(Path(path).read_text(encoding='utf-8'))
  self.assertEqual(data.get('provider','').lower(),provider.lower())
  funcs=data.get('functions'); self.assertIsInstance(funcs,list); self.assertTrue(funcs, 'provider export contains no functions')
  for f in funcs[:100]:
   self.assertTrue(f.get('entry'), 'function missing entry address')
   self.assertIsInstance(f.get('instructions',[]),list)
   self.assertIsInstance(f.get('calls',[]),list)
   self.assertIsInstance(f.get('xrefs',[]),list)
   self.assertIsInstance(f.get('basicBlocks',[]),list)
   for b in f.get('basicBlocks',[]):
    self.assertTrue(b.get('start')); self.assertIsInstance(b.get('successors',[]),list)
 def test_real_ghidra_export_if_configured(self):
  p=os.environ.get('REA_GHIDRA_TEST_JSON')
  if not p: self.skipTest('Set REA_GHIDRA_TEST_JSON to a Ghidra ExportFunctions.java JSON output')
  self.validate_functions(p,'Ghidra')
 def test_real_ida_export_if_configured(self):
  p=os.environ.get('REA_IDA_TEST_JSON')
  if not p: self.skipTest('Set REA_IDA_TEST_JSON to an IDA ida_export.py JSON output')
  self.validate_functions(p,'IDA')
 def test_real_jadx_tree_if_configured(self):
  p=os.environ.get('REA_JADX_TEST_DIR')
  if not p: self.skipTest('Set REA_JADX_TEST_DIR to a real JADX output directory')
  d=analyze_jadx_tree(p)
  self.assertIsInstance(d['permissions'],list); self.assertIsInstance(d['components'],list); self.assertIsInstance(d['crossReferences'],list)
if __name__=='__main__': unittest.main()
