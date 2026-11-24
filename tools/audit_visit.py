"""Verify query coverage, first-visit trust acquisition and native proofs before aggregating latency."""
from pathlib import Path
import csv,hashlib,itertools,json,math,statistics,tarfile
from collections import defaultdict
ROOT=Path(__file__).resolve().parents[1]/'tests'/'fixtures'/'lotte'
OUT=Path(__file__).resolve().parents[1]/'results'/'history'
METHODS=('raw','vida_per_token','vida_batched','block_fast')
CODES=(0,1,2,5)
SCOPES=('coarse','fine','rerank','all')
LABELS=('Strawman / Raw','VIDA 逐 token','VIDA 查询批处理','最新版纯 Block')
CN=('粗码本','细码本','候选文档重排','完整查询')
def load(path):return json.loads(path.read_text(encoding='utf-8'))
def filehash(path):
    h=hashlib.sha256()
    with path.open('rb') as f:
        for part in iter(lambda:f.read(4<<20),b''):h.update(part)
    return h.hexdigest()
def write_csv(path,rows):
    with path.open('w',encoding='utf-8-sig',newline='') as f:
        out=csv.DictWriter(f,fieldnames=list(rows[0]))
        out.writeheader();out.writerows(rows)
def receipts(path):
    found={}
    with path.open('rb') as f:
        for line in f:
            if not line.endswith(b'\n'):break
            r=json.loads(line);key=r['id']
            assert key not in found and r['tls']=='TLSv1.3' and not r['reused']
            found[key]=(r['method'],r['stage'],r['payload_bytes'])
    return found

def audit(phase,archive,identity,queries,origin_file):
    plan_path=ROOT/(phase+'-plan.json');plan=load(plan_path);identity=load(identity)
    manifest=load(ROOT/'run-manifest.json');published=load(ROOT/'publication.json')
    ref={a['query_id']:a for a in map(json.loads,(ROOT/'native-reference.jsonl').read_text().splitlines())}
    assert set(ref)==set(range(2931)) and queries and queries<=set(plan['ids'])
    assert plan['ids']==[0,2857] if phase=='smoke' else sorted(plan['ids'])==list(range(2931))
    assert plan['policies']==list(CODES) and plan['stages']==list(range(4)) and plan['caches']==['first_visit']
    warm,rep=plan['warmups'],plan['repeats']
    assert (warm,rep)==((0,1) if phase=='smoke' else (2,5))
    assert identity['binary']==manifest['binary_sha256'] and identity['plan']==filehash(plan_path)
    assert identity['native_reference']==filehash(ROOT/'native-reference.jsonl') and identity['client_trust']=='fresh_tls_signed_manifests'
    assert identity['owner_keys_sha256']==manifest['sources_and_inputs']['client-runtime/anchors.bin']
    assert identity['certificate_sha256']==manifest['sources_and_inputs']['client-runtime/source.pem']
    assert manifest['cpu_affinity']=='16-31' and manifest['threads']==16 and manifest['conditions_per_round']==16
    assert all(r['documents']==2428854 for r in manifest['owner_roots'].values())
    origin=receipts(origin_file)
    observed=set();acquisitions=set();medians=[];formal=warming=full=0
    expected=set(itertools.product(METHODS,SCOPES,range(warm+rep)))
    fetched_times=defaultdict(list)
    with tarfile.open(archive,'r|gz') as tar:
        for member in tar:
            assert member.isfile() and member.name.startswith('q') and member.name.endswith('.jsonl')
            q=int(Path(member.name).stem[1:]);assert q in queries and q not in observed;observed.add(q)
            seen=set();order=set();groups=defaultdict(list);bills={};stage_answers={}
            for line in tar.extractfile(member):
                r=json.loads(line)
                m,s,round_id=r['policy'],r['stage'],r['round']
                cell=(m,s,round_id);pos=(round_id,r['position'])
                assert cell in expected and cell not in seen and pos not in order and 0<=r['position']<16
                seen.add(cell);order.add(pos)
                assert r['query_id']==q and r['warmup']==(round_id<warm)
                assert r['cache_policy']=='first_visit' and r['digest_fetches']==1 and r['reference_parity'] and r['verified']
                assert r['owner_documents']==2428854 and r['cpu_affinity']=='16-31' and r['threads']==16
                code=CODES[METHODS.index(m)];st=SCOPES.index(s);layout=[8,32,128] if code==5 else [1,1,1]
                assert r['layout']==layout and r['stage_methods']==[code]*3
                d=r['digest'];key=d['id'];packet=published['packets'][f'{m}.{s}.bin']
                assert len(key)==32 and key not in acquisitions and origin[key]==(m,s,packet['bytes'])
                acquisitions.add(key)
                assert d['tls']=='TLSv1.3' and not d['session_reused'] and d['origin_verified'] and d['receipt_checked']
                assert d['source_manifests']==1 and d['stage_manifests']==(3 if st==3 else 1)
                assert d['payload_bytes']==packet['bytes'] and d['body_sha256']==packet['sha256']
                assert all(d[k]>0 for k in ('connect_tls_ms','http_ms','verify_derive_ms','http_header_bytes','http_request_bytes'))
                assert r['digest_wall_ms']+1e-6>=sum(d[k] for k in ('connect_tls_ms','http_ms','verify_derive_ms'))
                pins=published['methods'][m]
                assert r['new_index_pin']==ref[q]['snapshot']==pins['index']
                assert r['new_stage_pins']==[v if st==3 or i==st else '0'*64 for i,v in enumerate(pins['stages'])]
                net=(r['request_bytes']+r['response_bytes'])/37500
                assert math.isclose(net,r['modeled_transfer_ms'],abs_tol=1e-7)
                wall=sum(r[k] for k in ('digest_wall_ms','request_encode_ms','server_wall_ms','client_wall_ms','orchestration_ms'))
                assert r['orchestration_ms']>=-.002 and math.isclose(wall,r['transaction_wall_ms'],abs_tol=1e-7)
                assert math.isclose(wall+net,r['modeled_e2e_ms'],abs_tol=1e-7)
                bill=r['wire_parts'];assert sum(bill.values())==r['response_bytes']
                assert bills.setdefault((m,s),bill)==bill
                if st==3:
                    assert r['scope']=='query_e2e' and r['execution_digest']==ref[q]['execution_digest']
                    assert r['server_phases']['candidates']==ref[q]['candidates'] and r['server_phases']['ranked']==100
                else:
                    assert r['scope']=='stage_e2e' and r['height']==layout[st]
                    assert stage_answers.setdefault(s,r['execution_digest'])==r['execution_digest']
                    assert (bill['raw_coordinate_bytes']>0)==(code==0)
                    assert (bill['row_or_block_commitment_bytes']>0)==(code!=0)
                    assert bill['similarity_table_bytes']==(0 if code==0 else 4*32*r['real_rows'])
                    if st==2:
                        assert r['candidate_count']==ref[q]['candidates']==1024 and r['real_rows']==ref[q]['rerank_tokens']
                        assert bill['standalone_candidate_length_bytes']==4*r['candidate_count']
                    if code in (1,2):
                        proofs=32 if code==1 else 1
                        assert bill['aggregated_claim_bytes']==32*proofs and bill['ipa_argument_bytes']==544*proofs
                    elif code==5:assert bill['projection_or_direct_opening_bytes']>0 and bill['ipa_argument_bytes']>0
                if r['warmup']: warming+=1;continue
                formal+=1;full+=st==3
                groups[m,s].append(r)
                fetched_times[m,s].append(r['digest_wall_ms'])
            assert seen==expected
            for m in METHODS:
                complete=bills[m,'all'];assert complete['search_structure_source_signature_result_and_full_framing_bytes']>0
                for k in bills[m,'coarse']:assert complete[k]==sum(bills[m,stage][k] for stage in SCOPES[:3])
            for (m,s),sample in groups.items():
                assert len(sample)==rep
                sample.sort(key=lambda x:x['modeled_e2e_ms']);center=sample[rep//2]
                medians.append(dict(query=q,policy=m,stage=s,median_ms=center['modeled_e2e_ms'],
                    mean_repeats_ms=statistics.mean(r['modeled_e2e_ms'] for r in sample),
                    digest_ms=center['digest_wall_ms'],server_ms=center['server_wall_ms'],client_ms=center['client_wall_ms'],
                    transfer_ms=center['modeled_transfer_ms'],request_encode_ms=center['request_encode_ms'],orchestration_ms=center['orchestration_ms'],
                    digest_payload_bytes=center['digest']['payload_bytes'],request_bytes=center['request_bytes'],response_bytes=center['response_bytes'],
                    rerank_tokens=ref[q]['rerank_tokens']))
    assert observed==queries and (formal,warming,full)==(len(queries)*16*rep,len(queries)*16*warm,len(queries)*4*rep)
    check=dict(queries=len(queries),records=formal+warming,formal=formal,warmups=warming,integrated=full,
        query_cells=len(medians),origin_receipts_matched=len(acquisitions),distinct_origin_receipts_seen=len(origin),
        binary_sha256=identity['binary'],smoke_plan_sha256=filehash(ROOT/'smoke-plan.json'))
    return medians,fetched_times,check

