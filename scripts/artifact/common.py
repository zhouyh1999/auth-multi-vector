"""Paths, content identities and private run directories for the artifact CLI."""
import hashlib
import json
import os
import re
from pathlib import Path
import subprocess
try:
    import tomllib as tomli
except ImportError:
    import tomli

ROOT = Path(__file__).resolve().parents[2]
CONFIG = tomli.loads((ROOT / 'config.toml').read_text())
METHODS = ('raw', 'vida_per_token', 'vida_batched', 'block_fast')
CODES = (0, 1, 2, 5)
SCOPES = ('coarse', 'fine', 'rerank', 'all')


def require(condition, message):
    if not condition:
        raise ValueError(message)


def within(relative):
    path = ROOT / relative
    require(path == path.resolve() and path.is_relative_to(ROOT) and path != ROOT,
            f'path must resolve inside this copy: {relative}')
    return path


def output(relative, tree):
    path = within(relative)
    require(path.is_relative_to(ROOT / tree) and path != ROOT / tree,
            f'expected an output inside {tree}: {path}')
    # Same-device bind mounts are invisible to Path.is_mount().
    for line in Path('/proc/self/mountinfo').read_text().splitlines():
        mount = Path(re.sub(r'\\([0-7]{3})', lambda m: chr(int(m[1],8)), line.split()[4]))
        if mount != ROOT and mount.is_relative_to(ROOT):
            require(not (mount.is_relative_to(path) or path.is_relative_to(mount)), f'nested mount: {mount}')
    for file in path.rglob('*'):
        require(not file.is_symlink() and (not file.is_file() or file.stat().st_nlink == 1),
                f'linked output: {file}')
    return path


def digest(path):
    h = hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(8 << 20), b''):
            h.update(block)
    return h.hexdigest()


def read(path):
    return json.loads(path.read_bytes())


def write(path, obj):
    tmp = path.with_suffix('.pending')
    tmp.write_text(json.dumps(obj, indent=2) + '\n')
    tmp.replace(path)


def check_files(root, catalog):
    for name, item in catalog.items():
        path = root / name
        require(path.resolve() == path and path.is_relative_to(root), f'invalid input path {name}')
        require(path.is_file() and path.stat().st_size == item['size'] and digest(path) == item['sha256'],
                f'input integrity failure: {name}')


def binary(name):
    return within(os.environ.get('CARGO_TARGET_DIR', CONFIG['paths']['target'])) / 'release' / name


def execute(name, *args):
    subprocess.run([binary(name), *args], check=True)


def environment(dataset):
    os.environ['RAYON_NUM_THREADS'] = str(CONFIG[dataset]['threads'])
    native = ROOT / 'third_party/native'
    os.environ['PATH'] = str(native / 'bin') + os.pathsep + os.environ['PATH']
    os.environ['LD_LIBRARY_PATH'] = str(native / 'lib')
    os.environ['PYTHONNOUSERSITE'] = '1'

