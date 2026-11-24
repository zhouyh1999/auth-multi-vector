"""Verify exact coverage and one-to-one correspondence with fresh origin receipts."""
import itertools
import json
import math
from .common import CODES, CONFIG, METHODS, SCOPES, binary, digest, read, require, within, write
from .run import plan_for


def audit(dataset, work, run, *, recorded_binary=None):
    # Archived measurements can be inspected using only the shipped trust and native fixtures.
    if recorded_binary is None:
        expected_binary = digest(binary('first-visit'))
        anchors = work / 'bundles/anchors.bin'
        pins = {m: (work / 'bundles' / (m + '.pins')).read_bytes() for m in METHODS}
    else:
        expected_binary = recorded_binary
        anchors = work / 'public/anchors.bin'
        published = read(work / 'publication.json')['methods']
        pins = {m: bytes.fromhex(published[m]['index'] + ''.join(published[m]['stages'])) for m in METHODS}
    require(all(len(value) == 128 for value in pins.values()), 'pin set')

    plan = read(run / 'plan.json')
    require(plan == plan_for(dataset, plan['label']), 'plan order or policy changed')
    records = run / 'records'
    ident = read(records / 'identity.json')
    require(ident['binary'] == expected_binary and ident['plan'] == digest(run / 'plan.json'),
            'binary or plan identity changed')
    refs = work / 'native-reference.jsonl'
    require(ident['native_reference'] == digest(refs) and ident['certificate_sha256'] ==
            digest(run / 'client-runtime/source.pem') and ident['owner_keys_sha256'] ==
            digest(anchors), 'reference or trust identity changed')
    native = {r['query_id']: r for r in map(json.loads, refs.read_bytes().splitlines())}
    require(set(native) == set(range(2931 if dataset == 'lotte' else 1)), 'native reference coverage')
    require(ident['threads'] == CONFIG[dataset]['threads'] and ident['network_mbps'] == 300 and
            ident['rtt_ms'] == 0 and ident['sample'] == len(plan['ids']) and
            ident['client_trust'] == 'fresh_tls_signed_manifests', 'runtime profile')
    receipts = {}
    for line in (run / 'origin/origin-receipts.jsonl').read_bytes().splitlines():
        r = json.loads(line)
        require(r['id'] not in receipts and r['tls'] == 'TLSv1.3' and not r['reused'], 'duplicate or reused TLS session')
        receipts[r['id']] = r
    count = full = warm = 0
    require({p.name for p in records.glob('q*.jsonl')} == {f'q{i:04}.jsonl' for i in plan['ids']}, 'query files')
    packets = {f.name: (f.stat().st_size, digest(f)) for f in (work / 'public').glob('*.bin')}
    for q in plan['ids']:
        missing = set(itertools.product(plan['policies'], plan['stages'], range(plan['warmups'] + plan['repeats'])))
        answers = {}
        for line in (records / f'q{q:04}.jsonl').read_bytes().splitlines():
            r = json.loads(line)
            m, stage = r['policy'], r['stage']
            code, idx = CODES[METHODS.index(m)], SCOPES.index(stage)
            cell = (code, idx, r['round'])
            require(cell in missing and r['query_id'] == q and r['verified'] and r['reference_parity'], 'request coverage')
            missing.remove(cell)
            layout = [8,32,128] if code == 5 else [1,1,1]
            require(r['layout'] == layout and r['stage_methods'] == [code]*3 and r['digest_fetches'] == 1, 'route')
            require(r['cache_policy'] == 'first_visit' and r['threads'] == ident['threads'] and
                    r['cpu_affinity'] == ident['cpu_affinity'] and r['owner_documents'] == ident['owner_documents'],
                    'per-request runtime identity')
            d = r['digest']
            receipt = receipts.pop(d['id'])
            require((receipt['method'], receipt['stage'], receipt['payload_bytes']) == (m,stage,d['payload_bytes'])
                    and d['tls'] == 'TLSv1.3' and not d['session_reused'] and d['origin_verified'] and d['receipt_checked']
                    and d['stage_manifests'] == (3 if idx == 3 else 1) and d['source_manifests'] == 1, 'receipt')
            require(packets[f'{m}.{stage}.bin'] == (d['payload_bytes'], d['body_sha256']), 'publication bytes')
            method_pins = pins[m]
            require(r['new_index_pin'] == method_pins[:32].hex() == native[q]['snapshot'] == ident['source'] and r['new_stage_pins'] ==
                    [method_pins[32+i*32:64+i*32].hex() if idx in (3,i) else '00'*32 for i in range(3)], 'fetched pins')
            bill = r['wire_parts']
            wall = sum(r[k] for k in ('digest_wall_ms','request_encode_ms','server_wall_ms','client_wall_ms','orchestration_ms'))
            net = (r['request_bytes'] + r['response_bytes']) / 37500
            require(sum(bill.values()) == r['response_bytes'] and math.isclose(net, r['modeled_transfer_ms'])
                    and math.isclose(wall, r['transaction_wall_ms']) and math.isclose(wall+net,r['modeled_e2e_ms']), 'accounting')
            require(r['warmup'] == (r['round'] < plan['warmups']), 'round classification')
            if idx == 3:
                require(r['execution_digest'] == native[q]['execution_digest'] and
                        r['server_phases']['candidates'] == native[q]['candidates'] and
                        r['server_phases']['ranked'] == native[q]['result_count'], 'complete search')
                full += not r['warmup']
            else:
                if 'stage_digests' in native[q]:
                    require(r['execution_digest'] == native[q]['stage_digests'][idx], 'native stage matrix')
                require(r['height'] == layout[idx] and answers.setdefault(idx, r['execution_digest']) == r['execution_digest'],
                        'authenticated matrix comparison')
                require(bill['similarity_table_bytes'] == (0 if code == 0 else 4*32*r['real_rows']), 'table encoding')
                if code in (1,2):
                    proofs = 32 if code == 1 else 1
                    require(bill['ipa_argument_bytes'] == 544*proofs and bill['aggregated_claim_bytes'] == 32*proofs, 'IPA count')
                if code == 5:
                    require(bill['projection_or_direct_opening_bytes'] > 0 and bill['ipa_argument_bytes'] > 0, 'block proof')
            warm += r['warmup']
            count += 1
        require(not missing, 'missing requests')
    require(not receipts and read(records/'status.json')['state'] == 'complete', 'orphan receipt or incomplete run')
    summary = dict(binary=ident['binary'], plan=ident['plan'], queries=len(plan['ids']), requests=count,
                   full=full, warmup=warm, formal=count-warm, matched_receipts=count)
    if recorded_binary is None:
        write(run/'audit.json', summary)
    return summary
