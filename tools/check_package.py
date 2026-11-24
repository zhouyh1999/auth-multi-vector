"""Verify delivered source, fixture and dependency bytes using only the standard library."""
import hashlib
import json
from pathlib import Path


def main():
    root = Path(__file__).resolve().parents[1]
    manifest = json.loads((root / 'docs/source-manifest.json').read_bytes())
    verified = {}
    for entry in manifest['files']:
        name = entry['destination']
        path = root / name
        if not path.is_relative_to(root) or path.resolve() != path:
            raise ValueError(f'unsafe manifest path {name}')
        expected = entry['delivered_sha256']
        if expected is None:
            if path.exists():
                raise ValueError(f'retired path is present: {name}')
            continue
        if name not in verified:
            with path.open('rb') as stream:
                digest = hashlib.sha256()
                for block in iter(lambda: stream.read(1 << 20), b''):
                    digest.update(block)
            verified[name] = digest.hexdigest()
        if verified[name] != expected:
            raise ValueError(f'SHA-256 mismatch: {name}')
    print(f'{len(verified)} distinct delivered files match their SHA-256 digests')


if __name__ == '__main__':
    main()

