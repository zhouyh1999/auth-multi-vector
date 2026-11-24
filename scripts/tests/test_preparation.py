"""Exercise owner checkpoint reuse and byte-level reproducibility with the release tools."""
import tempfile
import unittest
import sys
import subprocess
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from artifact.common import ROOT, binary, digest, environment
from artifact.data import prepare, reference


class OwnerPreparationTests(unittest.TestCase):
    def test_fresh_preparation_and_checkpoint_integrity(self):
        environment('sample')
        with tempfile.TemporaryDirectory(dir=ROOT/'artifacts') as tmp:
            roots = [Path(tmp)/name for name in ('first', 'second')]
            for work in roots:
                work.mkdir()
                prepare('sample',work)
                reference('sample',work)
            a,b = roots
            names = ['inputs/trusted.json','native-reference.jsonl']
            for subdir in ('public','bundles','native-material'):
                names.extend(str(p.relative_to(a)) for p in (a/subdir).rglob('*') if p.is_file())
            self.assertEqual({p:digest(a/p) for p in names}, {p:digest(b/p) for p in names})
            # A source with changed bytes must not accept the completed shard marker.
            raw = a/'inputs/raw.npy'
            changed = bytearray(raw.read_bytes())
            changed[-1] ^= 1
            raw.write_bytes(changed)
            stale_input = subprocess.run([binary('population-owner'), a, 'row'], capture_output=True)
            self.assertNotEqual(stale_input.returncode, 0)
            self.assertIn(b'completed material shard', stale_input.stderr)

            file = b/'native-material/0000000/points-1.bin'
            original = bytearray(file.read_bytes())
            original[0] ^= 1
            file.write_bytes(original)
            rejected = subprocess.run([binary('population-owner'), b, 'row'], capture_output=True)
            self.assertNotEqual(rejected.returncode,0)
            self.assertIn(b'completed material shard', rejected.stderr)

            # Simulate a stopped writer: partial output exists but no final receipt.
            (file.parent/'row.done').unlink()
            file.write_bytes(b'partial')
            subprocess.run([binary('population-owner'), b, 'row'], check=True, capture_output=True)
            self.assertEqual(file.read_bytes(), (a/'native-material/0000000/points-1.bin').read_bytes())
            self.assertEqual((file.parent/'row.done').read_bytes(),
                             (a/'native-material/0000000/row.done').read_bytes())

