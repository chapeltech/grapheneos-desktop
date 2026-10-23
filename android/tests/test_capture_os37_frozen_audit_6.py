import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

SOURCE=Path(__file__).resolve().parents[1]/'tools/capture_os37_frozen_audit_6.py'
spec=importlib.util.spec_from_file_location('os37_audit_capture',SOURCE)
c=importlib.util.module_from_spec(spec);spec.loader.exec_module(c)


class CaptureTests(unittest.TestCase):
    def test_actual_child_raw_pid_terminal_and_inputs_not_synthetic_receipt(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td);source=root/'input';source.write_bytes(b'owned input');out=root/'evidence';out.mkdir()
            argv=['/usr/bin/python3','-B','-c',
                "import os,json;print(json.dumps(dict(kind='OS37_readonly_independent_frozen_product_audit',host_pid=os.getpid(),runtime_qualified=False,image_qualified=False)))"]
            with patch.object(c,'resources',return_value={'/u':999}):
                result=c.capture(argv,out,{source:c.ref(source)['sha256']})
            actual=json.loads((out/'audit.stdout.json').read_text())
            self.assertEqual(actual['host_pid'],result['child_pid']);self.assertGreater(result['child_pid'],0)
            self.assertEqual(result['returncode'],0);self.assertEqual(result['argv'],argv)
            self.assertTrue(result['small_immutable_inputs_conserved'])
            self.assertEqual(result['stdout'],c.ref(out/'audit.stdout.json'))
            self.assertTrue((out/'started.json').is_file());self.assertTrue((out/'child-started.json').is_file())

    def test_actual_failure_preserves_raw_and_primary(self):
        with tempfile.TemporaryDirectory() as td:
            out=Path(td)
            with patch.object(c,'resources',return_value={'/u':999}),self.assertRaises(ValueError):
                c.capture(['/usr/bin/python3','-B','-c',"import sys;print('original failure',file=sys.stderr);sys.exit(3)"],out,{})
            result=json.loads((out/'receipt.json').read_text())
            self.assertEqual(result['status'],'not_passed');self.assertEqual(result['returncode'],3)
            self.assertIn('original failure',(out/'audit.stderr').read_text())
            self.assertIn('Actual unchanged auditor failed',result['primary_error'])

    def test_hash_drift_and_original_four_floors_reject(self):
        with tempfile.TemporaryDirectory() as td:
            path=Path(td)/'input';path.write_text('original');expected={path:c.ref(path)['sha256']}
            path.write_text('changed')
            with self.assertRaises(ValueError):c.inputs(expected)
        free={p:floor for p,floor in c.FLOORS.items()};free['/u']+=c.LOSS_CAP
        def usage(path):return type('Usage',(),{'free':free[path]})()
        with patch.object(c.shutil,'disk_usage',side_effect=usage):
            c.resources(admission=True)
            for p in free:
                original=free[p];free[p]=c.FLOORS[p]-1
                with self.assertRaises(ValueError):c.resources()
                free[p]=original
            with self.assertRaises(ValueError):c.resources({p:v+c.LOSS_CAP+1 for p,v in free.items()})
        self.assertEqual(c.FLOORS,{'/':52*c.GIB,'/var':8*c.GIB,'/tmp':32*c.GIB,'/u':c.GIB//2})


if __name__=='__main__':unittest.main()
