#!/usr/bin/env python3
"""Prepare, run and audit a first-visit dataset from this workspace."""
import argparse
import fcntl
import json
import os
import subprocess
from pathlib import Path

from artifact.audit import audit
from artifact.common import CONFIG, METHODS, binary, ROOT, environment, output, require, within
from artifact.data import import_lotte, prepare, reference, validate
from artifact.run import benchmark, plan_for


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('command', choices=('validate-data','import','prepare','reference','benchmark','test-e2e','audit','report'))
    parser.add_argument('--dataset', choices=('sample','lotte'), required=True)
    parser.add_argument('--plan', choices=('sample','smoke','prefix512','full'))
    parser.add_argument('--source', type=Path, help='directory containing inputs/ and native-material/')
    parser.add_argument('--run', help='run directory relative to the workspace')
    parser.add_argument('--recorded-binary', metavar='SHA256',
                        help='audit archived records using packaged public and native fixtures')
    args = parser.parse_args()
    os.chdir(ROOT)
    os.umask(0o077)
    dataset = args.dataset
    environment(dataset)
    if args.recorded_binary is not None:
        import re
        require(args.command == 'audit' and args.run and re.fullmatch('[0-9a-f]{64}', args.recorded_binary),
                'archived audit requires an explicit run and expected binary SHA-256')
        run = output(args.run, 'results')
        require(run.parent == within(Path(CONFIG['paths']['results']) / dataset), 'run belongs to another dataset')
        fixtures = within(Path(CONFIG['paths']['fixtures']).parent / dataset)
        print(json.dumps(audit(dataset, fixtures, run, recorded_binary=args.recorded_binary)))
        return
    work = output(CONFIG[dataset]['work'], 'artifacts')
    work.mkdir(parents=True, exist_ok=True)
    with (work / '.lock').open('a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        if args.command == 'import':
            require(dataset == 'lotte' and args.source, 'import needs --dataset lotte --source DIR')
            import_lotte(args.source, work)
        elif args.command == 'validate-data':
            validate(dataset, work)
        elif args.command == 'prepare':
            prepare(dataset, work)
        elif args.command == 'reference':
            validate(dataset, work)
            reference(dataset, work)
        elif args.command in ('audit','report'):
            parent = output(Path(CONFIG['paths']['results']) / dataset, 'results')
            if args.run:
                run = output(args.run, 'results')
                require(run.parent == parent, 'run belongs to another dataset')
            else:
                run = max((p.parent.parent for p in parent.glob('*/records/status.json')),
                          key=lambda p: p.stat().st_mtime_ns)
            if args.command == 'report':
                from artifact.report import report
                report(dataset, work, run)
                print(run / 'summary.csv')
            else:
                print(json.dumps(audit(dataset, work, run)))
        else:
            label = args.plan or ('sample' if dataset == 'sample' else 'smoke')
            plan = plan_for(dataset, label)
            if args.command == 'test-e2e':
                prepare(dataset, work)
                if dataset == 'sample':
                    reference(dataset, work)
            else:
                validate(dataset, work)
            run = benchmark(dataset, work, plan)
            print(json.dumps(audit(dataset, work, run)))
            if dataset == 'sample' and args.command == 'test-e2e':
                frozen = ROOT/'tests/fixtures/sample'
                index = (work/'bundles/raw.pins').read_bytes()[:32]
                for method in METHODS:
                    current = (run/'fixtures'/f'{method}.request').read_bytes()
                    previous = (frozen/'wire'/f'{method}.request').read_bytes()
                    require(current[:32] == index and current[32:] == previous[32:], 'request codec changed')
                with (run / 'rejections.json').open('w') as output_file:
                    subprocess.run([binary('first-visit'), 'check-fixture', work/'public', run/'fixtures'],
                                   stdout=output_file,check=True)


if __name__ == '__main__':
    main()

