"""Audit the two published, disjoint prefixes and summarize query-weighted latency."""
import argparse
import json
import sys
from pathlib import Path
import numpy as np
from audit_visit import ROOT, OUT, METHODS, SCOPES, audit, filehash, load, write_csv


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--plot', action='store_true')
    args = parser.parse_args()
    if not __debug__:
        raise RuntimeError('archival checks require Python assertions')
    sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
    from artifact.common import output
    output(OUT, 'results')
    OUT.mkdir(parents=True, exist_ok=True)
    ids = load(ROOT/'full-plan.json')['ids']
    evidence = []
    medians = []
    for first, last in [(1,256), (257,512)]:
        base = ROOT/'archives'/f'qorder-{first:04}-{last:04}'
        archive = base.with_suffix('.tar.gz')
        receipts = base.with_name(base.name+'-origin.jsonl')
        for path, suffix in [(archive,'-sha256.json'),(receipts,'-origin.sha256.json')]:
            if filehash(path) != load(base.with_name(base.name+suffix))['sha256']:
                raise ValueError(f'archive checksum: {path}')
        rows, _, check = audit('full', archive, ROOT/'records/full/identity.json', set(ids[first-1:last]), receipts)
        evidence.append(check)
        medians.extend(rows)
    if len({(r['query'],r['policy'],r['stage']) for r in medians}) != 512*16:
        raise ValueError('overlapping or missing queries')
    (OUT/'audit.json').write_text(json.dumps(evidence,indent=2)+'\n')
    stats = []
    for method in METHODS:
        for stage in SCOPES:
            values = [r['median_ms'] for r in medians if (r['policy'],r['stage']) == (method,stage)]
            stats.append(dict(policy=method, stage=stage, mean_ms=np.mean(values),
                              p10_ms=np.quantile(values,.1),p90_ms=np.quantile(values,.9)))
    write_csv(OUT/'summary.csv',stats)
    write_csv(OUT/'per-query.csv',medians)
    if args.plot:
        from analyze import render
        render(stats, 512)
    print(json.dumps(evidence))


if __name__ == '__main__':
    main()

