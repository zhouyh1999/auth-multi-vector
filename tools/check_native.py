"""Compare recomputed LoTTE native traces and observed stage matrices with the frozen references."""
import argparse
import gzip
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
STAGES = ('coarse', 'fine', 'rerank')
METHODS = ('raw', 'vida_per_token', 'vida_batched', 'block_fast')


def require(condition, message):
    if not condition:
        raise ValueError(message)


def load_reference(path):
    frozen = ROOT / 'tests/fixtures/lotte/native-reference.jsonl'
    golden = {row['query_id']: row for row in map(json.loads, frozen.read_bytes().splitlines())}
    require(set(golden) == set(range(2931)), 'frozen coverage')
    records = {}
    opener = gzip.open if path.suffix == '.gz' else open
    with opener(path, 'rb') as stream:
        for row in map(json.loads, stream):
            q = row['query_id']
            require(q in golden and q not in records, f'duplicate or unknown query {q}')
            require(all(row[k] == v for k, v in golden[q].items()), f'frozen reference {q}')
            ids = row['candidate_ids']
            ranks = row['ranking']
            require(ids == sorted(set(ids)) and len(ids) == row['candidates'] and
                    len({hit['doc_id'] for hit in ranks}) == len(ranks) == row['result_count'] and
                    all(hit['doc_id'] in ids for hit in ranks), f'candidate or ranking shape {q}')
            require(len(row['stage_digests']) == 3, f'missing stage matrix {q}')
            records[q] = dict(zip(STAGES, row['stage_digests']), all=row['execution_digest'])
    require(records.keys() == golden.keys(), 'recomputed coverage')
    return records


def check_run(run, references):
    plan = json.loads((run / 'plan.json').read_bytes())
    stages = (*STAGES, 'all')
    rounds = plan['repeats'] + plan['warmups']
    count = 0
    for q in plan['ids']:
        cells = {(METHODS[(0, 1, 2, 5).index(code)], stages[s], i)
                 for code in plan['policies'] for s in plan['stages'] for i in range(rounds)}
        with (run / 'records' / f'q{q:04}.jsonl').open('rb') as stream:
            for r in map(json.loads, stream):
                cell = (r['policy'], r['stage'], r['round'])
                require(cell in cells and r['query_id'] == q and r['verified'], f'invalid record {q} {cell}')
                require(r['execution_digest'] == references[q][r['stage']], f'native digest {q} {cell}')
                cells.remove(cell)
                count += 1
        require(not cells, f'missing cells for {q}')
    return {'plan': plan['label'], 'queries': len(plan['ids']), 'matched_records': count}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('reference', type=Path, help='recomputed JSONL or .jsonl.gz')
    parser.add_argument('runs', type=Path, nargs='+')
    args = parser.parse_args()
    refs = load_reference(args.reference)
    print(json.dumps({'native_queries': len(refs), 'runs': [check_run(run, refs) for run in args.runs]}))


if __name__ == '__main__':
    main()

