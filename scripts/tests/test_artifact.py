import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from artifact import common
from artifact.audit import audit
from artifact.data import catalog
from artifact.run import plan_for


class ArtifactTests(unittest.TestCase):
    def test_sample_manifest_and_raw_ranking(self):
        import numpy as np
        source, manifest = catalog('sample')
        common.check_files(source, manifest)
        query = np.floor(np.load(source/'queries.npy')[0].astype(np.float64)*32767).astype(np.int64)
        docs = np.floor(np.load(source/'raw.npy').astype(np.float64)*32767).astype(np.int64)
        offsets = np.fromfile(source/'token-offsets.u64',dtype='<u8')
        scores = sorted((int(32*32767**2 - (query @ docs[a:b].T).max(axis=1).sum()),i)
                        for i,(a,b) in enumerate(zip(offsets,offsets[1:])))
        self.assertEqual(common.read(source/'expected.json')['ranking'],
                         [dict(doc_id=i,distance=s) for s,i in scores[:3]])

    def test_prefix_coverage(self):
        ids = plan_for('lotte','full')['ids']
        prefix = plan_for('lotte','prefix512')
        self.assertEqual(prefix['ids'], ids[:512])
        self.assertEqual(len(set(ids)), 2931)
        self.assertEqual(prefix['stages'], [3])
        self.assertEqual(prefix['policies'], list(common.CODES))

    def test_linked_output_is_rejected_before_write(self):
        with tempfile.TemporaryDirectory() as tmp, patch.object(common, 'ROOT', Path(tmp)):
            root = Path(tmp)
            work = root/'artifacts/data'
            work.mkdir(parents=True)
            other = root/'old'
            other.write_text('original')
            (work/'link').symlink_to(other)
            with self.assertRaises(ValueError): common.output('artifacts/data','artifacts')
            (work/'link').unlink()
            os.link(other, work/'hard')
            with self.assertRaises(ValueError): common.output('artifacts/data','artifacts')
            with self.assertRaises(ValueError): common.output('artifacts/../old','artifacts')
            self.assertEqual(other.read_text(), 'original')

    def test_manifest_rejects_same_size_change(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            path = root/'vector'
            path.write_bytes(b'1234')
            record = {'vector': {'size':4, 'sha256':common.digest(path)}}
            path.write_bytes(b'1243')
            with self.assertRaisesRegex(ValueError,'integrity'): common.check_files(root,record)

