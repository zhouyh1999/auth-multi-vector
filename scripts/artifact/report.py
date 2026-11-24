"""Reduce repeated measurements within each query before aggregating across queries."""
import csv
import json
import statistics
from collections import defaultdict

from .audit import audit


def report(dataset, work, run):
    import matplotlib
    matplotlib.use('Agg')
    import matplotlib.pyplot as plt
    import numpy as np

    audit(dataset, work, run)
    groups = defaultdict(list)
    for path in sorted((run/'records').glob('q*.jsonl')):
        for row in map(json.loads, path.read_bytes().splitlines()):
            if not row['warmup']:
                groups[row['query_id'],row['policy'],row['stage']].append(row)
    fields = ('digest_wall_ms','server_wall_ms','client_wall_ms','request_encode_ms','orchestration_ms',
              'transaction_wall_ms','modeled_transfer_ms','modeled_e2e_ms','request_bytes','response_bytes')
    cells = []
    by_route = defaultdict(list)
    for (q,m,s), rows in sorted(groups.items()):
        median = sorted(rows,key=lambda r:r['modeled_e2e_ms'])[len(rows)//2]
        cells.append({'query_id':q,'policy':m,'stage':s,'repeats':len(rows), **{k:median[k] for k in fields}})
        by_route[m,s].append(median)
    summaries = []
    for (m,s),rows in by_route.items():
        scores = [r['modeled_e2e_ms'] for r in rows]
        summaries.append(dict(policy=m, stage=s, queries=len(rows), p10_ms=np.quantile(scores,.1),
                              p90_ms=np.quantile(scores,.9),
                              **{'mean_'+k:statistics.fmean(r[k] for r in rows) for k in fields}))
    for name, data in [('per-query.csv',cells),('summary.csv',summaries)]:
        with (run/name).open('w',newline='') as stream:
            writer = csv.DictWriter(stream,fieldnames=list(data[0]))
            writer.writeheader()
            writer.writerows(data)
    stages = list(dict.fromkeys(r['stage'] for r in summaries))
    fig, axes = plt.subplots(1,len(stages),figsize=(4*len(stages),3.5),squeeze=False,layout='constrained')
    for ax, stage in zip(axes.flat, stages):
        rows = sorted((r for r in summaries if r['stage']==stage),key=lambda r:r['policy'])
        for y,row in enumerate(rows):
            ax.hlines(y, row['p10_ms'], row['p90_ms'],color='steelblue')
            ax.plot(row['mean_modeled_e2e_ms'],y,'o',color='black')
        ax.set_yticks(range(len(rows)),[r['policy'] for r in rows])
        ax.set_xscale('log')
        ax.set_title(stage)
        ax.set_xlabel('Modeled end-to-end (ms)')
    fig.suptitle(f'{dataset} · {len({r["query_id"] for r in cells})} queries · mean and P10–P90')
    fig.savefig(run/'latency.svg')
    plt.close(fig)

