"""Compare fresh first-visit records with every archived pre-reorganization repeat."""
import argparse
import csv
import hashlib
import json
import math
import statistics
import sys
import tarfile
from collections import defaultdict
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
FIXTURE = ROOT / 'tests/fixtures/lotte'
METHODS = ('raw', 'vida_per_token', 'vida_batched', 'block_fast')
OLD_BINARY = '40011cba9cab18d92c3f17665dc35867cd45f995e09f806f1b73fa3007610589'
NEW_BINARY = '3d4ceebbd332440fb2859b7ef4bbf9868d5939a28cfd86dff6506e0f639409d3'
FIELDS = ('cache_policy', 'candidate_count', 'digest_fetches', 'execution_digest', 'height',
          'layout', 'method', 'new_index_pin', 'new_stage_pins', 'owner_documents', 'policy',
          'query_id', 'real_rows', 'reference_parity', 'request_bytes', 'response_bytes',
          'scope', 'stage', 'stage_methods', 'threads', 'verified', 'wire_parts')
TIMES = ('modeled_e2e_ms', 'transaction_wall_ms', 'server_wall_ms', 'client_wall_ms',
         'modeled_transfer_ms', 'digest_wall_ms')


def read(path):
    return json.loads(path.read_bytes())


def sha(path):
    h = hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(1 << 20), b''):
            h.update(block)
    return h.hexdigest()


def require(test, message):
    if not test:
        raise ValueError(message)


def signature(row):
    return {
        **{key: row[key] for key in FIELDS},
        'candidates': row['server_phases']['candidates'],
        'ranked': row['server_phases']['ranked'],
        **{key: row['digest'][key] for key in
           ('body_sha256', 'payload_bytes', 'source_manifests', 'stage_manifests')}
    }


def match(left, right, label):
    differences = [field for field in left if left[field] != right[field]]
    require(not differences, f'{label}: {differences}')


def read_run(directory, ids):
    audit = read(directory / 'audit.json')
    identity = read(directory / 'records/identity.json')
    expected = {name: 2048 for name in ('full', 'formal', 'requests', 'matched_receipts')}
    expected.update(warmup=0, queries=512, binary=NEW_BINARY)
    require(all(audit[k] == v for k, v in expected.items()), f'audit {directory}')
    require(read(directory / 'plan.json')['ids'] == ids and identity['plan'] == sha(directory / 'plan.json'),
            f'plan {directory}')
    result = {}
    for q in ids:
        for row in map(json.loads, (directory / 'records' / f'q{q:04}.jsonl').read_bytes().splitlines()):
            key = (q, row['policy'])
            require(row['query_id'] == q and (row['stage'], row['warmup'], row['round']) == ('all', False, 0)
                    and key not in result, f'new record {key}')
            require(row['verified'] and row['reference_parity'], f'new verifier {key}')
            result[key] = row
    require(set(result) == {(q, m) for q in ids for m in METHODS}, 'new coverage')
    return identity, result


def write_csv(path, rows):
    with path.open('w', newline='', encoding='utf-8') as stream:
        writer = csv.DictWriter(stream, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('run', type=Path)
    args = parser.parse_args()
    out = Path(__file__).resolve().parent
    prior_dir = ROOT / 'results/lotte/prefix512-hg0oo473'
    require(args.run.resolve() != prior_dir, 'select a fresh run')
    ids = read(FIXTURE / 'full-plan.json')['ids'][:512]
    prior_id, previous = read_run(prior_dir, ids)
    new_id, current = read_run(args.run, ids)
    old_id = read(FIXTURE / 'records/full/identity.json')
    require(old_id['binary'] == OLD_BINARY and new_id['binary'] == prior_id['binary'] == NEW_BINARY, 'release')
    for field in ('owner_keys_sha256', 'native_reference', 'source', 'network_mbps', 'rtt_ms', 'threads'):
        require(old_id[field] == new_id[field] == prior_id[field], f'baseline identity {field}')
    require(new_id['plan'] == prior_id['plan'] and new_id['cpu_affinity'] == prior_id['cpu_affinity'], 'rerun identity')
    require(len({s['certificate_sha256'] for s in (new_id, old_id, prior_id)}) == 3, 'new certificate')
    fresh_ids = {r['digest']['id'] for r in current.values()}
    require(len(fresh_ids) == 2048 and fresh_ids.isdisjoint({r['digest']['id'] for r in previous.values()}),
            'fresh receipts')
    for key, row in current.items():
        match(signature(row), signature(previous[key]), f'prior new release {key}')

    old_times = defaultdict(list)
    archive_checks = []
    sys.path.insert(0, str(ROOT / 'tools'))
    from audit_visit import audit as audit_archive
    require(__debug__, 'archive verification requires Python assertions')
    for start, stop in ((1, 256), (257, 512)):
        base = FIXTURE / 'archives' / f'qorder-{start:04}-{stop:04}'
        archive = base.with_suffix('.tar.gz')
        receipts = base.with_name(base.name + '-origin.jsonl')
        for path, suffix in ((archive, '-sha256.json'), (receipts, '-origin.sha256.json')):
            require(sha(path) == read(base.with_name(base.name + suffix))['sha256'], f'archive digest {path}')
        _, _, checked = audit_archive('full', archive, FIXTURE / 'records/full/identity.json',
                                      set(ids[start-1:stop]), receipts)
        require(checked['integrated'] == 5120 and checked['queries'] == 256, 'historic coverage')
        archive_checks.append(checked)
        with tarfile.open(archive, 'r|gz') as tar:
            for member in tar:
                for row in map(json.loads, tar.extractfile(member)):
                    if row['stage'] != 'all' or row['warmup']:
                        continue
                    key = row['query_id'], row['policy']
                    match(signature(current[key]), signature(row), f'old release {key} round {row["round"]}')
                    require(row['digest']['id'] not in fresh_ids, 'reused old acquisition ID')
                    old_times[key].append({field:row[field] for field in TIMES})
    require(old_times.keys() == current.keys() and all(len(vals) == 5 for vals in old_times.values()),
            'five archived formal observations per cell')

    paired = []
    for q in ids:
        for method in METHODS:
            key = q, method
            row = current[key]
            # Keep all time components from the SAME old observation ranked third by total time.
            center = sorted(old_times[key], key=lambda x:x['modeled_e2e_ms'])[2]
            pair = dict(query_id=q, method=method, old_repeats=5,
                        candidates=row['server_phases']['candidates'], ranked=row['server_phases']['ranked'],
                        execution_digest=row['execution_digest'], request_bytes=row['request_bytes'],
                        response_bytes=row['response_bytes'], fresh_receipt=row['digest']['id'])
            for field in TIMES:
                pair['old_' + field] = center[field]
                pair['previous_new_' + field] = previous[key][field]
                pair['rerun_' + field] = row[field]
            pair['paired_delta_pct'] = 100 * (row['modeled_e2e_ms'] / center['modeled_e2e_ms'] - 1)
            paired.append(pair)
    write_csv(out / 'paired-queries.csv', paired)

    summaries = []
    for method in METHODS:
        group = [p for p in paired if p['method'] == method]
        summary = dict(method=method, queries=len(group))
        for field in TIMES:
            for prefix in ('old', 'previous_new', 'rerun'):
                key = prefix + '_' + field
                summary[key] = statistics.fmean(p[key] for p in group)
        for label in ('old', 'previous_new'):
            summary['change_vs_' + label + '_pct'] = 100 * (summary['rerun_modeled_e2e_ms']
                                                            / summary[label + '_modeled_e2e_ms'] - 1)
        changes = [p['paired_delta_pct'] for p in group]
        deciles = statistics.quantiles(changes, n=10, method='inclusive')
        summary.update(paired_p10_pct=deciles[0], paired_median_pct=statistics.median(changes),
                       paired_p90_pct=deciles[8], mean_response_bytes=statistics.fmean(p['response_bytes'] for p in group))
        require(all(math.isfinite(x) for x in summary.values() if isinstance(x, float)), 'nonfinite statistic')
        summaries.append(summary)
    write_csv(out / 'comparison.csv', summaries)
    validation = dict(fresh_run=args.run.name, queries=len(ids), paired_cells=len(paired),
                      formal_old_full_requests=sum(map(len, old_times.values())),
                      fresh_full_requests=len(current), matched_fresh_receipts=len(fresh_ids),
                      previous_new_full_requests=len(previous), exact_field_mismatches=0,
                      checked_fields=list(signature(next(iter(current.values())))),
                      comparisons_with_old=10240, comparisons_with_previous_new=2048,
                      fresh_certificate_unique=True, identity=dict(old=old_id, previous_new=prior_id, rerun=new_id),
                      old_archives=archive_checks)
    (out / 'validation.json').write_text(json.dumps(validation, indent=2) + '\n')
    print(json.dumps({key: validation[key] for key in ('queries','paired_cells','formal_old_full_requests',
          'fresh_full_requests','matched_fresh_receipts','exact_field_mismatches')}))


if __name__ == '__main__':
    main()
