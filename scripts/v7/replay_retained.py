#!/usr/bin/env python3
"""Reopen retained real C0 evidence and evaluate new client application.
No fresh guest execution, no agent/model and no cloud use. All failed rows kept.
The V6 storage index and custody index are evidence inputs, never guest claims.
"""
import argparse, copy, gzip, hashlib, json, os, pathlib, re, statistics, subprocess, time

def enc(v):
    return json.dumps(v, sort_keys=True, separators=(',', ':')).encode()

def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--export', type=pathlib.Path, required=True)
    ap.add_argument('--custody', type=pathlib.Path, required=True)
    ap.add_argument('--client', type=pathlib.Path, required=True)
    ap.add_argument('--blake3', type=pathlib.Path, required=True)
    ap.add_argument('--output', type=pathlib.Path, required=True)
    a = ap.parse_args()
    a.output = a.output.resolve(); a.client = a.client.resolve(); a.output.mkdir(mode=0o700)
    os.chmod(a.output, 0o700)
    helper_sha = hashlib.sha256(a.blake3.read_bytes()).hexdigest()
    if helper_sha != '39968746cb782d25cc631ea5dd9a6f530856916f0b04ed99e4fd38d0a489cd51':
        raise ValueError('independent digest helper differs from retained verified V6 helper')
    def b3(b):
        return subprocess.check_output([str(a.blake3)], input=b).decode().strip()
    assert b3(b'abc') == '6437b3ac38465133ffb63b75273a8db548c558465d79db03fd359c6cd5bd9d85'
    storage = json.loads((a.export / 'storage-manifest.json').read_text())
    index = {r['path']: r for r in storage['entries'] if r['kind'] == 'regular'}
    provenance = []
    def raw(name):
        e = index[name]; chunks = []
        for ref in e['stored_files']:
            b = (a.export / ref['path']).read_bytes()
            assert len(b) == ref['bytes'] and hashlib.sha256(b).hexdigest() == ref['sha256']
            chunks.append(b)
        stored = b''.join(chunks)
        assert hashlib.sha256(stored).hexdigest() == e['stored_sha256']
        b = gzip.decompress(stored) if e['encoding'] == 'gzip' else stored
        assert len(b) == e['raw_bytes'] and hashlib.sha256(b).hexdigest() == e['raw_sha256']
        provenance.append({'source_path': name, 'sha256': e['raw_sha256'], 'bytes': len(b)})
        return b
    def load(name): return json.loads(raw(name))
    def packed(b):
        assert b.startswith(b'REALM-PORTABLE-3\n'); off = len(b'REALM-PORTABLE-3\n')
        def frame():
            nonlocal off
            n = int.from_bytes(b[off:off+8], 'big'); off += 8
            out = b[off:off+n]; off += n; return out
        run, envelope = json.loads(frame()); n = int.from_bytes(b[off:off+4], 'big'); off += 4
        blobs = {}
        for _ in range(n):
            key = frame().decode(); value = frame(); blobs[key] = value
        assert off == len(b)
        return run, envelope, blobs
    rows = []; command_id = 0
    def save(path, v): path.write_text(json.dumps(v, indent=2)+'\n'); os.chmod(path, 0o600)
    def cmd(argv, expected=0):
        nonlocal command_id
        command_id += 1; started = time.perf_counter_ns()
        p = subprocess.run([str(a.client), *map(str, argv)], capture_output=True)
        elapsed = time.perf_counter_ns() - started
        prefix = a.output/f'cmd-{command_id:04d}'
        prefix.with_suffix('.stdout').write_bytes(p.stdout); prefix.with_suffix('.stderr').write_bytes(p.stderr)
        rows.append({'kind': 'command', 'argv': list(map(str, argv)), 'exit_status': p.returncode, 'expected': expected, 'passed': p.returncode == 0 if expected == 0 else p.returncode != 0, 'elapsed_ns': elapsed, 'stdout_sha256': hashlib.sha256(p.stdout).hexdigest(), 'stderr_sha256': hashlib.sha256(p.stderr).hexdigest(), 'stdout_file': prefix.name+'.stdout', 'stderr_file': prefix.name+'.stderr'})
        save(a.output/'progress.json', rows)
        return p, rows[-1]
    def private(p): p.mkdir(mode=0o700); os.chmod(p, 0o700); return p
    def setup(case, contract):
        dest = private(case/'dest'); state = private(case/'state')
        (dest/'input.txt').write_bytes(bytes(contract['input_bytes'])); os.chmod(dest/'input.txt', contract['input_mode'])
        sentinel = case/'outside-sentinel'; sentinel.write_bytes(b'not-authorized'); os.chmod(sentinel, 0o600)
        return dest, state, sentinel
    custody = json.loads(a.custody.read_text())
    assert custody['source_revision'] == '71c7e756b73521301764cebcbc21e1bb89cfd839' and custody['status'] == 'PASS'
    accepted = custody['cases']
    success = []; latencies = []
    for n, old in enumerate(accepted):
        source_name = old['artifact']; pos = source_name.index('campaigns/'); artifact_name = source_name[pos:]
        prefix = artifact_name.removesuffix('evidence/accepted.realm')
        publication = prefix+'publication/'
        if prefix.startswith('campaigns/foundation71Race/'):
            publication = 'campaigns/foundation71Race/shared-00/'
        ctl = publication+'.live.realm-control/'
        artifact = raw(artifact_name)
        assert hashlib.sha256(artifact).hexdigest() == old['sha256']
        run, envelope, blobs = packed(artifact)
        ev_ref = next(r for r in run['evidence'] if r['id'] == 'v6-checked-c1')
        checked = json.loads(blobs[ev_ref['digest']['value']])
        contract = checked.get('file_contract') or {'input_bytes':list(b'abc'),'input_mode':0o644,'output_path':'output.txt','output_bytes':list(b'ABC'),'output_mode':0o600}
        transitions = [load(name) for name in index if name.startswith(ctl+'lifecycle/transitions/')]
        assert len(transitions) == 1
        tr = transitions[0]; genesis = load(ctl+'lifecycle/GENESIS.json'); head = load(ctl+'lifecycle/HEAD.json')
        receipt = raw(ctl+'receipts/'+tr['generation_identity']['publication_id']+'.json')
        retained = publication+'.live.realm-generation-'+tr['generation_identity']['generation_id']+'/input.txt'
        assert raw(retained) == bytes(contract['input_bytes'])
        def world(data):
            entries = {name:{'File':{'content_blake3':b3(b),'mode':mode}} for name,b,mode in data}
            return b3(enc(entries))
        before = world([('input.txt',bytes(contract['input_bytes']),contract['input_mode'])])
        after = world([('input.txt',bytes(contract['input_bytes']),contract['input_mode']),(contract['output_path'],bytes(contract['output_bytes']),contract['output_mode'])])
        assert before == tr['parent_world_root'] and after == head['world_root']
        proof = {'schema_version':1,'genesis':genesis,'snapshot':{'head':head,'transitions':transitions,'artifacts':{tr['artifact_digest']['value']:list(artifact)},'receipts':{tr['receipt_digest']['value']:list(receipt)},'journal':list(raw(ctl+'publication.jsonl')),'live_world_root':after,'retained_world_roots':{tr['generation_identity']['generation_id']:before}}}
        permit = {'schema_version':1,'artifact_blake3':b3(artifact),'genesis_root':genesis['domain'], 'exact_head_root':head['authority_root'],'contract':contract}
        # External pins taken from the retained worker/operator record, not the
        # new client's verdict or the .realm's self-reported success.
        external = load(prefix+'evidence/operator-pins.json')
        published = load(prefix+'evidence/public-accept.json')
        permit['genesis_root'] = external['genesis_root']
        assert permit['exact_head_root'] == published['public_accept_report']['authority_head_root']
        case = private(a.output/f'case-{n:02d}'); af = case/'accepted.realm'; af.write_bytes(artifact)
        pf=case/'proof.json'; tf=case/'external-permit.json'; save(pf,proof); save(tf,permit)
        dest,state,sentinel=setup(case,contract)
        stage={}; started=time.perf_counter_ns()
        for label,args in [('artifact', ['artifact','verify',af,pf,tf]),('preflight',['apply','preflight',af,pf,tf,dest])]:
            p,row=cmd(args); stage[label]=row['elapsed_ns']; assert row['passed'],p.stderr
            if label=='preflight': approval=re.search(rb'ID: ([a-f0-9]{64})',p.stdout)[1].decode()
        p,row=cmd(['apply','run',af,pf,tf,dest,state,'--approve',approval]); stage['apply']=row['elapsed_ns']; assert row['passed'],p.stderr
        p,row=cmd(['apply','verify',af,pf,tf,dest,state]); stage['verify']=row['elapsed_ns']; assert row['passed'],p.stderr
        elapsed=time.perf_counter_ns()-started
        # Independent physical state, not client's report, is the case oracle.
        expected={ 'input.txt':bytes(contract['input_bytes']),contract['output_path']:bytes(contract['output_bytes']) }
        assert sorted(x.name for x in dest.iterdir()) == sorted(expected)
        for name,b in expected.items(): assert (dest/name).read_bytes()==b
        assert (dest/contract['output_path']).stat().st_mode & 0o7777 == 0o600
        assert (dest/contract['output_path']).stat().st_nlink == 1
        assert sentinel.read_bytes()==b'not-authorized'
        ino=(dest/contract['output_path']).stat().st_ino
        p,row=cmd(['apply','resume',af,pf,tf,dest,state,'--approve',approval]); assert row['passed'],p.stderr
        assert (dest/contract['output_path']).stat().st_ino==ino
        success.append({'case':n,'origin_run':checked['run_id'],'source_revision':'71c7e756b73521301764cebcbc21e1bb89cfd839','classification':'RETAINED_REAL_C0_TO_FRESH_HOST_STATE_VERIFIED','fresh_guest':False,'agent':False,'total_client_ns':elapsed,'stages_ns':stage,'artifact_bytes':len(artifact),'proof_bytes':pf.stat().st_size})
        latencies.append(elapsed)
        save(a.output/'positive-progress.json',success)
        if n==0: base=(artifact,proof,permit,contract)
    attacks=[]
    artifact,proof,permit,contract=base
    def negative(label, mutate):
        case=private(a.output/f'attack-{len(attacks):02d}-{label}'); af=case/'artifact.realm';pf=case/'proof.json';tf=case/'permit.json'
        b=bytearray(artifact);p=copy.deepcopy(proof);t=copy.deepcopy(permit)
        mutate(b,p,t);af.write_bytes(b);save(pf,p);save(tf,t)
        proc,row=cmd(['artifact','verify',af,pf,tf],1)
        attacks.append({'case':label,'expected':'REFUSE','passed':row['passed'],'kind':'artifact_or_trust_tampering','command_row':len(rows)-1})
    for pos in [0,5,15,16,32,64,128,256,512,1024,2048,len(artifact)-1]:
        negative(f'byte-{pos}',lambda b,p,t,pos=pos:b.__setitem__(pos,b[pos]^1))
    negative('truncated',lambda b,p,t:b.__delitem__(slice(len(b)-8,None)))
    negative('extra-byte',lambda b,p,t:b.extend(b'x'))
    proof_mutations={
      'proof-version':lambda p:p.update(schema_version=99),
      'missing-artifacts':lambda p:p['snapshot']['artifacts'].clear(),
      'missing-receipts':lambda p:p['snapshot']['receipts'].clear(),
      'missing-transitions':lambda p:p['snapshot']['transitions'].clear(),
      'empty-journal':lambda p:p['snapshot'].update(journal=[]),
      'torn-journal':lambda p:p['snapshot']['journal'].pop(),
      'missing-retained':lambda p:p['snapshot']['retained_world_roots'].clear(),
      'wrong-live-world':lambda p:p['snapshot'].update(live_world_root='a'*64),
      'wrong-head':lambda p:p['snapshot']['head'].update(authority_root='a'*64),
      'old-head-sequence':lambda p:p['snapshot']['head'].update(sequence=0),
      'fake-head-world':lambda p:p['snapshot']['head'].update(world_root='a'*64),
      'unknown-head-schema':lambda p:p['snapshot']['head'].update(schema_version=999),
      'unknown-genesis-schema':lambda p:p['genesis'].update(schema_version=999),
      'fake-genesis-label':lambda p:p['genesis'].update(label='trust-me'),
      'fake-genesis-world':lambda p:p['genesis'].update(initial_world_root='a'*64),
      'fake-genesis-workspace':lambda p:p['genesis'].update(workspace_identity='a'*64),
      'missing-parent':lambda p:p['snapshot']['transitions'][0].update(parent_authority_root='a'*64),
      'wrong-delta':lambda p:p['snapshot']['transitions'][0].update(delta_root='a'*64),
      'wrong-transition-world':lambda p:p['snapshot']['transitions'][0].update(world_root='a'*64),
      'duplicate-transition':lambda p:p['snapshot']['transitions'].append(copy.deepcopy(p['snapshot']['transitions'][0])),
    }
    for label,mut in proof_mutations.items(): negative(label,lambda b,p,t,mut=mut:mut(p))
    for field in ['schema_version','artifact_blake3','genesis_root','exact_head_root']:
        negative('permit-'+field,lambda b,p,t,field=field:t.update({field:99 if field=='schema_version' else '0'*64}))
    for path in ['', '..','../escape','/outside','a/b','a\\b','input.txt','.', 'out\nside', 'x'*65]:
        negative('path-'+str(len(attacks)),lambda b,p,t,path=path:t['contract'].update(output_path=path))
    for label,field,value in [('wrong-output','output_bytes',[0]),('wrong-input','input_bytes',[0]),('wrong-output-mode','output_mode',0o644),('wrong-input-mode','input_mode',0o666),('too-large','input_bytes',[0]*129)]:
        negative(label,lambda b,p,t,field=field,value=value:t['contract'].update({field:value}))
    for mode in ['changed-input','extra-file','output-exists','output-symlink','input-hardlink','input-symlink','unsafe-dest-mode','dest-symlink','extra-directory']:
        case=private(a.output/f'attack-{len(attacks):02d}-{mode}');af=case/'artifact.realm';pf=case/'proof.json';tf=case/'permit.json';af.write_bytes(artifact);save(pf,proof);save(tf,permit)
        dest,state,sentinel=setup(case,contract)
        if mode=='changed-input': (dest/'input.txt').write_bytes(b'changed')
        elif mode=='extra-file': (dest/'extra').write_bytes(b'x')
        elif mode=='output-exists': (dest/contract['output_path']).write_bytes(bytes(contract['output_bytes']))
        elif mode=='output-symlink': (dest/contract['output_path']).symlink_to(sentinel)
        elif mode=='input-hardlink': os.link(dest/'input.txt',case/'outside-alias')
        elif mode=='input-symlink': (dest/'input.txt').unlink();(dest/'input.txt').symlink_to(sentinel)
        elif mode=='unsafe-dest-mode': os.chmod(dest,0o755)
        elif mode=='extra-directory': (dest/'nested').mkdir()
        else: alias=case/'alias';alias.symlink_to(dest,target_is_directory=True);dest=alias
        proc,row=cmd(['apply','preflight',af,pf,tf,dest],1)
        attacks.append({'case':mode,'expected':'REFUSE','passed':row['passed'],'kind':'host-precondition','command_row':len(rows)-1})
        assert sentinel.read_bytes()==b'not-authorized'
    ordered=sorted(latencies)
    report={'schema_version':1,'scope':'retained real V6 C0 publication -> fresh local macOS client; no fresh guest/model execution','new_client_revision':subprocess.check_output(['git','rev-parse','HEAD']).decode().strip(),'source_dirty_at_run':bool(subprocess.check_output(['git','status','--porcelain']).strip()),'client_source_sha256':{name:hashlib.sha256(pathlib.Path(name).read_bytes()).hexdigest() for name in ['Cargo.lock','crates/realm-artifact/src/lib.rs','crates/realm-artifact/src/lifecycle.rs','crates/realm-artifact/src/host_apply.rs','crates/realm-cli/Cargo.toml','crates/realm-cli/src/main.rs','crates/realm-cli/src/closed_loop.rs']},'client_sha256':hashlib.sha256(a.client.read_bytes()).hexdigest(),'host':os.uname().sysname,'positive_cases':success,'focused_adversarial':attacks,'passed':all(r['passed'] for r in rows),'metrics':{'host_success_rate':len(success)/len(accepted),'client_false_accept_observed':sum(not r['passed'] for r in attacks),'adversarial_n':len(attacks),'warm_process_client_p50_ns':statistics.median(latencies),'warm_process_client_p95_ns':ordered[max(0,int(len(ordered)*0.95)-1)],'first_process_client_ns':latencies[0],'agent_task_accuracy':None,'fresh_vm_startup':None,'fresh_e2e_latency':None,'false_refusal_rate':0.0,'cost_per_task':None,'power_loss_validation':None},'unverified':['fresh Linux/KVM V7 execution','contained coding agent','20 meaningful end-to-end coding tasks','true storage-cold measurement','2x end-to-end improvement','power-loss durability','hostile same-UID/root writers'],'provenance':provenance,'no_cloud_use':True}
    save(a.output/'report.json',report)
    print(json.dumps({'passed':report['passed'],'positive_cases':len(success),'adversarial_cases':len(attacks),'client_p50_ms':report['metrics']['warm_process_client_p50_ns']/1e6,'report':str(a.output/'report.json')}))
    if not report['passed']: raise SystemExit(1)
if __name__=='__main__': main()
