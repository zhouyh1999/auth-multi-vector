"""Execute one immutable plan using a newly created origin and trust directory."""
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

from .common import CONFIG, ROOT, execute, output, read, require, within, write


def plan_for(dataset, label):
    fixtures = within(CONFIG['paths']['fixtures'])
    if dataset == 'sample':
        require(label == 'sample', 'sample requires sample plan')
        plan = read(fixtures / 'smoke-plan.json')
        plan.update(label=label, ids=[0])
    elif label == 'prefix512':
        plan = read(fixtures / 'full-plan.json')
        plan.update(label=label, ids=plan['ids'][:512], stages=[3], repeats=1, warmups=0)
    else:
        require(label in ('full', 'smoke'), 'invalid LoTTE plan')
        plan = read(fixtures / (label + '-plan.json'))
    return plan


def benchmark(dataset, data, plan):
    parent = output(Path(CONFIG['paths']['results']) / dataset, 'results')
    parent.mkdir(parents=True, exist_ok=True)
    run = Path(tempfile.mkdtemp(prefix=plan['label'] + '-', dir=parent))
    write(run / 'plan.json', plan)
    origin = run / 'origin'
    client = run / 'client-runtime'
    origin.mkdir(mode=0o700)
    client.mkdir(mode=0o700)
    print(run, flush=True)
    with (run / 'origin.log').open('w') as log:
        proc = subprocess.Popen([sys.executable, ROOT / 'scripts/artifact/origin.py', origin,
                                 data / 'public'], stdout=log, stderr=subprocess.STDOUT)
        try:
            deadline = time.monotonic() + 30
            while not (origin / 'connection.json').is_file():
                require(proc.poll() is None and time.monotonic() < deadline, f'origin failed: {log.name}')
                time.sleep(.05)
            for source, name in [(origin / 'source-v1.pem', 'source.pem'), (origin / 'auth-token', 'auth-token'),
                                 (origin / 'connection.json', 'connection.json'), (data / 'bundles/anchors.bin', 'anchors.bin')]:
                shutil.copyfile(source, client / name)
            execute('first-visit', data, run / 'plan.json', run)
        finally:
            (origin / 'stop-source').touch()
            try:
                proc.wait(10)
            except subprocess.TimeoutExpired:
                proc.terminate()
                proc.wait()
            for secret in (origin / 'source-v1.key', origin / 'auth-token', client / 'auth-token'):
                secret.unlink(missing_ok=True)
    return run
