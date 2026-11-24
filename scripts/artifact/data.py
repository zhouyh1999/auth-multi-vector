"""Materialize immutable data inputs and publish owner-authenticated bundles."""
import json
import os
from pathlib import Path
import shutil

from .common import CONFIG, check_files, digest, execute, read, require, within, write


def catalog(dataset):
    source = within(CONFIG[dataset]['inputs'])
    return source, read(source / 'files.json')


def validate(dataset, work):
    source, files = catalog(dataset)
    check_files(work if dataset == 'lotte' else source, files)


def import_lotte(source, work):
    _, files = catalog('lotte')
    source = source.resolve(strict=True)
    require(not source.is_relative_to(work) and not work.is_relative_to(source), 'overlapping import')
    for name in files:
        target = work / name
        require(target.resolve() == target and target.is_relative_to(work)
                and Path(name).parts[0] in ('inputs','native-material'), f'invalid import destination: {name}')
    for name, identity in files.items():
        target = work / name
        if target.exists():
            check_files(work, {name: identity})
            continue
        original = source / name
        require(original.is_file(), f'missing import file: {original}')
        target.parent.mkdir(parents=True, exist_ok=True)
        tmp = target.with_suffix(target.suffix + '.importing')
        shutil.copyfile(original, tmp)
        require(tmp.stat().st_size == identity['size'] and digest(tmp) == identity['sha256'], name)
        tmp.replace(target)


def sample_inputs(work):
    source, files = catalog('sample')
    inputs = work / 'inputs'
    binding = work / 'input-bindings.json'
    if binding.exists():
        require(read(binding) == files, 'sample input changed since preparation')
    for name in ['inputs', 'imported', 'owner-private', 'checkpoints/raw', 'checkpoints/compact',
                 'snapshots/raw/client', 'snapshots/raw/server', 'snapshots/compact/client',
                 'snapshots/compact/server']:
        (work / name).mkdir(parents=True, exist_ok=True)
    for name in files:
        shutil.copyfile(source / name, inputs / name)
    write(binding, files)
    shutil.copyfile(binding, inputs / binding.name)
    key = work / 'owner-private/owner.key'
    if not key.exists():
        with open(os.open(key, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600), 'wb') as stream:
            stream.write(bytes([17]) * 32)
    require(key.read_bytes() == bytes([17]) * 32, 'sample owner identity')
    execute('gem-prepare', work)
    for src, dst in [('server/offline.compact', 'offline.compact'), ('client/trusted.json', 'trusted.json')]:
        shutil.copyfile(work / 'snapshots/compact' / src, inputs / dst)
    for layout in ('block', 'row'):
        execute('population-owner', work, layout)


def prepare(dataset, work):
    validate(dataset, work)
    if dataset == 'sample':
        sample_inputs(work)
    bundles = work / 'bundles'
    bundles.mkdir(exist_ok=True)
    execute('bundle-owner', work, bundles)
    execute('first-visit', 'publish', bundles, work / 'public')
    if dataset == 'lotte':
        fixture = within(CONFIG['paths']['fixtures'])
        for f in (fixture / 'public').iterdir():
            require(digest(f) == digest(work / 'public' / f.name), f'publication mismatch: {f.name}')
        shutil.copyfile(fixture / 'native-reference.jsonl', work / 'native-reference.jsonl')


def reference(dataset, work):
    execute('gem-reference', work, *(['--compare-frozen'] if dataset == 'lotte' else []))
    if dataset == 'sample':
        row = read(work / 'native-reference.jsonl')
        expected = read(within(CONFIG['sample']['inputs']) / 'expected.json')
        for hit in row['ranking']:
            hit['distance'] = int(hit['distance'])
        require(all(row[key] == value for key, value in expected.items()), 'sample ranking or candidates')
    else:
        frozen = within(CONFIG['paths']['fixtures']) / 'native-reference.jsonl'
        from itertools import zip_longest
        with (work / 'recomputed-reference.jsonl').open('rb') as actual, frozen.open('rb') as golden:
            count = 0
            for output, original in zip_longest(actual,golden):
                require(output and original, 'reference coverage')
                a,g = json.loads(output),json.loads(original)
                require(all(a[k] == v for k,v in g.items()), f"native mismatch at query {g['query_id']}")
                count += 1
            require(count == 2931, 'frozen query coverage')
