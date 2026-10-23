#!/usr/bin/env python3
"""Frozen finite artifact/observation experiments. No model, VM or execution authority."""
import argparse, copy, hashlib, json, os, platform, signal, statistics, struct, subprocess, sys, tempfile, time
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
MAGIC = b'REALM-PORTABLE-3\n'

def digest(path): return hashlib.sha256(path.read_bytes()).hexdigest()
def frame(data): return struct.pack('>Q', len(data)) + data

def decode(data):
    if not data.startswith(MAGIC): raise ValueError('format')
    p = len(MAGIC)
    def take(n):
        nonlocal p
        if n < 0 or p+n > len(data): raise ValueError('truncated')
        x = data[p:p+n]; p += n; return x
    def block(): return take(struct.unpack('>Q', take(8))[0])
    meta = json.loads(block())
    blobs = [(block(), block()) for _ in range(struct.unpack('>I', take(4))[0])]
    if p != len(data): raise ValueError('trailing')
    return meta, blobs

def encode(meta, blobs):
    return MAGIC + frame(json.dumps(meta, sort_keys=True, separators=(',',':')).encode()) + struct.pack('>I', len(blobs)) + b''.join(frame(k)+frame(v) for k,v in blobs)

def measured(command, directory):
    """wait4 supplies per-child peak RSS. Startup is included in wall time."""
    started = time.perf_counter()
    with tempfile.TemporaryFile() as out, tempfile.TemporaryFile() as err:
        proc = subprocess.Popen([str(x) for x in command], stdout=out, stderr=err, cwd=directory)
        deadline = time.monotonic()+15
        while True:
            pid, status, usage = os.wait4(proc.pid, os.WNOHANG)
            if pid: break
            if time.monotonic() > deadline:
                proc.kill(); _, status, usage = os.wait4(proc.pid, 0)
                proc.returncode = os.waitstatus_to_exitcode(status)
                raise TimeoutError('checker exceeded 15 seconds')
            time.sleep(.001)
        proc.returncode = os.waitstatus_to_exitcode(status)
        out.seek(0); err.seek(0)
        return {'exit':proc.returncode,'seconds':time.perf_counter()-started,
                'peak_rss_kib':usage.ru_maxrss/(1024 if sys.platform=='darwin' else 1),
                'stdout':out.read().decode(), 'stderr':err.read().decode()}

def artifact_cases():
    original = (ROOT/'crates/realm-artifact/examples/minimal.realm').read_bytes()
    meta, blobs = decode(original)
    cases = []
    def add(name, raw, status, purpose):
        cases.append({'id':name,'bytes':raw,'expected':status,'purpose':purpose})
    add('intact', original, 'VALID', 'Complete unsealed synthetic fixture; authority unknown')
    for i in range(3):
        changed = [(k, v) for k,v in blobs]; key, payload = changed[i]
        altered = bytearray(payload); altered[-1] ^= 1; changed[i] = (key, bytes(altered))
        add(f'payload-{i}',encode(meta,changed),'INVALID','Referenced payload substitution')
    def change(name, edit, expected, purpose):
        m=copy.deepcopy(meta); b=copy.deepcopy(blobs); edit(m,b); add(name,encode(m,b),expected,purpose)
    change('foreign-evidence-run',lambda m,b:m[0]['evidence'][0].update(run_id='another-run'),'INVALID','Cross-run evidence')
    change('missing-evidence-id',lambda m,b:m[0]['observations'][0].update(evidence=['absent']),'INVALID','Dangling observation reference')
    change('duplicate-evidence',lambda m,b:m[0]['evidence'].append(copy.deepcopy(m[0]['evidence'][0])),'INVALID','Duplicate evidence IDs')
    change('missing-portable-blob',lambda m,b:b.pop(),'INVALID','Required portable bytes missing')
    change('thin-missing-blob',lambda m,b:(m[1].update(content='thin'),b.pop()),'INCOMPLETE','Thin transport preserves missing content honestly')
    change('future-schema',lambda m,b:m[0].update(schema_version=99),'UNSUPPORTED','Unsupported run schema')
    add('future-format',original.replace(MAGIC,b'REALM-PORTABLE-9\n',1),'UNSUPPORTED','Unsupported transport')
    add('truncated',original[:-7],'INVALID','Truncated payload')
    add('trailing',original+b'extra','INVALID','Trailing bytes')
    add('length-overflow',MAGIC+struct.pack('>Q',2**64-1),'INVALID','Hostile frame length')
    change('self-reported-accept',lambda m,b:m[1]['verification'][0].update(decision='ACCEPT'),'VALID','A forged reported decision cannot grant authority')
    change('consistent-false-effect',lambda m,b:m[0]['proposed_effects'][0].update(target='never-observed-file'),'VALID','Unsealed internally consistent assertion; semantics not checked')
    change('omitted-unknowns',lambda m,b:m[0].update(unknown_effects=[]),'VALID','Producer may omit unknowns; observation still UNKNOWN')
    change('hostile-display-text',lambda m,b:m[0]['observations'][0].update(target='<img src=x onerror=alert(1)>'),'VALID','Viewer must render hostile producer text literally')
    return cases

def suite_a(binary, output, repeats):
    folder=output/'a';folder.mkdir(); cases=artifact_cases()
    manifest=[]
    for case in cases:
        p=folder/(case['id']+'.realm');p.write_bytes(case['bytes'])
        manifest.append({k:v for k,v in case.items() if k!='bytes'}|{'sha256':digest(p)})
    # Freeze all expected outcomes and fixture bytes BEFORE any checker invocation.
    (folder/'manifest.json').write_text(json.dumps(manifest,indent=2)+'\n')
    rows=[]
    for case in cases:
        p=folder/(case['id']+'.realm')
        for repeat in range(repeats):
            result=measured([binary,'verify',p,'--json'],output)
            report=json.loads(result.pop('stdout'));stderr=result.pop('stderr')
            auth=measured([binary,'verify',p,'--json','--require-execution'],output)
            auth_report=json.loads(auth['stdout'])
            start=time.perf_counter(); data=p.read_bytes(); actual=hashlib.sha256(data).hexdigest(); baseline=actual==manifest[0]['sha256']; baseline_time=time.perf_counter()-start
            # The hash baseline's claim is ONLY exact equality with one externally pinned intact fixture.
            byte_equal=data==cases[0]['bytes']
            row={'case':case['id'],'repeat':repeat,'expected':case['expected'],'status':report['status'],
                 'correct':report['status']==case['expected'],'authorization':auth_report['checks']['execution_authorization'],
                 'authorization_request_status':auth_report['status'],'sha256_same_as_pinned_intact':baseline,
                 'sha256_byte_identity_correct':baseline==byte_equal,'sha256_seconds':baseline_time,**result}
            rows.append(row)
            (folder/f'{case["id"]}-{repeat}.json').write_text(json.dumps({'measurement':row,'report':report,'execution_request':auth_report,'stderr':stderr},indent=2)+'\n')
    accepted=[x for x in rows if x['status']=='VALID']; rejected=[x for x in rows if x['status']=='INVALID']
    summary={'cases':len(cases),'repeats':repeats,'measurements':len(rows),'per_case_correct':sum(x['correct'] for x in rows),
             'true_artifact_acceptance':sum(x['expected']=='VALID' for x in accepted),'false_artifact_acceptance':sum(x['expected']!='VALID' for x in accepted),
             'true_artifact_rejection':sum(x['expected']=='INVALID' for x in rejected),'false_artifact_rejection':sum(x['expected']!='INVALID' for x in rejected),
             'incomplete':sum(x['status']=='INCOMPLETE' for x in rows),'unsupported':sum(x['status']=='UNSUPPORTED' for x in rows),
             'false_execution_authorization':sum(x['authorization']!='NOT_CHECKED' for x in rows),
             'median_checker_ms':1000*statistics.median(x['seconds'] for x in rows),'peak_checker_rss_kib':max(x['peak_rss_kib'] for x in rows),
             'median_sha256_ms':1000*statistics.median(x['sha256_seconds'] for x in rows),'sha256_correct_byte_identity':sum(x['sha256_byte_identity_correct'] for x in rows),
             'baseline_claim':'Exact byte identity against externally pinned intact fixture; not semantic or authorization checking; in-process timing not speedup-comparable to CLI startup'}
    return summary,rows

WORKER = r"""import json,os,sys
from pathlib import Path
mode,seed=sys.argv[1],int(sys.argv[2]); root=Path('.')
log=[]
if mode=='inherited-input':
    seed=int(os.read(int(sys.argv[3]),64));log.append('read synthetic inherited input')
if mode in ('transient-forbidden-effect','omitted-observation','false-effect-report'):
    Path('protected.txt').write_text('changed')
    print('effect-visible',flush=True);input()
    Path('protected.txt').write_text('original')
    if mode=='transient-forbidden-effect':log.append('temporarily changed protected.txt')
if mode=='unexpected-file':Path('extra.txt').write_text('unexpected')
Path('calc.py').write_text('def add(a, b):\n    return a '+('-' if mode=='wrong-answer' else '+')+' b + '+str(seed)+'\n')
if mode=='false-effect-report':log.append('no protected file was modified')
else:log.append('updated calc.py')
print(json.dumps(log),flush=True)
"""

def suite_b(binary,output,config):
    folder=output/'b';folder.mkdir();worker=folder/'worker.py';worker.write_text(WORKER)
    tasks=[{'id':f'{mode}-{seed}','mode':mode,'seed':seed,'expected_task_correct':mode!='wrong-answer','expected_policy_violation':mode not in ('correct','wrong-answer')} for mode in config['coding_conditions'] for seed in config['coding_seeds']]
    (folder/'manifest.json').write_text(json.dumps(tasks,indent=2)+'\n')
    rows=[]
    for task in tasks:
      for repeat in range(config['suite_b_repeats']):
        case=folder/f'{task["id"]}-{repeat}';case.mkdir();work=case/'work';work.mkdir()
        before=b'def add(a, b):\n    return a - b\n';(work/'calc.py').write_bytes(before);(work/'protected.txt').write_text('original')
        (case/'before.txt').write_bytes(before)
        read,write=os.pipe();os.write(write,str(task['seed']).encode());os.close(write)
        started=time.perf_counter()
        proc=subprocess.Popen([sys.executable,'-I','-B',str(worker),task['mode'],str(task['seed']),str(read)],cwd=work,pass_fds=(read,),stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
        os.close(read);first=proc.stdout.readline();saw_intermediate=False
        if first.strip()=='effect-visible':
            saw_intermediate=(work/'protected.txt').read_text()=='changed'
            proc.stdin.write('\n');proc.stdin.flush();log=proc.stdout.readline()
        else:log=first
        _,stderr=proc.communicate(timeout=10)
        if proc.returncode:raise RuntimeError(stderr)
        controller_seconds=time.perf_counter()-started
        # A separate real process checks behavior, not the worker's reported result.
        probe=subprocess.run([sys.executable,'-I','-B','-c',f"exec(open('calc.py').read()); assert add(3,5)=={8+task['seed']}"],cwd=work,capture_output=True,text=True)
        supplied=log if task['mode']!='omitted-observation' else '[]\n'
        (case/'after.txt').write_bytes((work/'calc.py').read_bytes());(case/'supplied.log').write_text(supplied)
        record=measured([binary,'record',task['id'],case/'before.txt',case/'after.txt',case/'supplied.log',case/'observations.realm'],output)
        if record['exit']:raise RuntimeError(record)
        result=measured([binary,'verify',case/'observations.realm','--json','--require-execution'],output)
        report=json.loads(result.pop('stdout'));result.pop('stderr')
        # The harness has designed/observed these channels; it is NOT an exhaustive process monitor.
        actual_extra=(work/'extra.txt').exists()
        inherited=task['mode']=='inherited-input' and 'inherited' in log
        observed_violation=saw_intermediate or actual_extra or inherited
        log_detected='temporarily changed protected.txt' in supplied or 'inherited' in supplied or actual_extra
        row={'task':task['id'],'mode':task['mode'],'repeat':repeat,'task_correct':probe.returncode==0,
             'expected_task_correct':task['expected_task_correct'],'policy_violation_observed':observed_violation,
             'expected_policy_violation':task['expected_policy_violation'],'snapshot_log_policy_flag':log_detected,
             'artifact_status':report['status'],'artifact_integrity':report['checks']['artifact_integrity'],
             'execution_authorization':report['checks']['execution_authorization'],'controller_seconds':controller_seconds,
             'record_seconds':record['seconds'],'verify_seconds':result['seconds'],'peak_verify_rss_kib':result['peak_rss_kib']}
        (case/'result.json').write_text(json.dumps({'measurement':row,'checker_report':report,'probe_stdout':probe.stdout,'probe_stderr':probe.stderr,'independently_reopened_intermediate':saw_intermediate,'supplied_log':supplied},indent=2)+'\n')
        rows.append(row)
    summary={'tasks':len(tasks),'repeats':config['suite_b_repeats'],'executions':len(rows),
             'task_tests_passed':sum(x['task_correct'] for x in rows),'task_tests_failed':sum(not x['task_correct'] for x in rows),
             'observed_policy_violations':sum(x['policy_violation_observed'] for x in rows),
             'policy_violations_with_passing_task_tests':sum(x['policy_violation_observed'] and x['task_correct'] for x in rows),
             'snapshot_log_violations_flagged':sum(x['policy_violation_observed'] and x['snapshot_log_policy_flag'] for x in rows),
             'snapshot_log_false_flags':sum(not x['policy_violation_observed'] and x['snapshot_log_policy_flag'] for x in rows),
             'artifact_integrity_passes':sum(x['artifact_integrity']=='PASS' for x in rows),
             'authorization_incomplete':sum(x['artifact_status']=='INCOMPLETE' for x in rows),
             'false_execution_authorizations':sum(x['execution_authorization']!='NOT_CHECKED' for x in rows),
             'ground_truth_checks_match':all(x['task_correct']==x['expected_task_correct'] and x['policy_violation_observed']==x['expected_policy_violation'] for x in rows),
             'median_controller_ms':1000*statistics.median(x['controller_seconds'] for x in rows),
             'median_record_ms':1000*statistics.median(x['record_seconds'] for x in rows),
             'median_verify_ms':1000*statistics.median(x['verify_seconds'] for x in rows),
             'qualified_execution_condition':'NOT_RUN: no qualified coding custody/semantic authority is consumed by this harness',
             'scope':'28 finite Python controller tasks; no AI model, exhaustive observation, containment or live authorization'}
    return summary, rows

def source_record():
    """Git metadata when available; verified export manifest for a source archive."""
    if (ROOT/'.git').exists():
        return {'source_revision': subprocess.check_output(['git','rev-parse','HEAD'],cwd=ROOT,text=True).strip(),
                'source_dirty': bool(subprocess.check_output(['git','status','--porcelain'],cwd=ROOT)),
                'source_kind': 'git'}
    provenance = ROOT/'PROVENANCE.json'
    manifest = ROOT/'EXPORT_MANIFEST.json'
    if provenance.is_file() and manifest.is_file():
        pins = json.loads(manifest.read_text())
        if not all((ROOT/name).is_file() and digest(ROOT/name)==pin for name,pin in pins.items()):
            raise ValueError('source archive differs from its export manifest')
        return {'source_revision': json.loads(provenance.read_text())['source_revision'],
                'source_dirty': None, 'source_kind': 'verified_export_manifest',
                'source_manifest_sha256': digest(manifest)}
    return {'source_revision': 'UNKNOWN', 'source_dirty': None, 'source_kind': 'unversioned_files'}

def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--checker',type=Path,required=True);parser.add_argument('--output',type=Path,required=True);args=parser.parse_args()
    output=args.output.resolve();output.mkdir(parents=True,mode=0o700,exist_ok=False);binary=args.checker.resolve(strict=True)
    config=json.loads((ROOT/'benchmarks/config.json').read_text())
    provenance=source_record()
    source_paths=['benchmarks/run.py','benchmarks/config.json','crates/realm-artifact/src/inspection.rs','crates/realm-artifact/src/observations.rs','crates/realm-artifact/examples/minimal.realm']
    report={'schema':'realm.launch-results.v1',**provenance,
            'source_sha256':{p:digest(ROOT/p) for p in source_paths},'binary_sha256':digest(binary),'platform':platform.platform(),'architecture':platform.machine(),
            'python':platform.python_version(),'config':config,'status':'INCOMPLETE','authority':'NONE'}
    (output/'provenance.json').write_text(json.dumps(report,indent=2)+'\n')
    report['a'],a=suite_a(binary,output,config['suite_a_repeats']);report['b'],b=suite_b(binary,output,config)
    report['status']='PASS' if all(x['correct'] for x in a) and report['b']['ground_truth_checks_match'] and not report['a']['false_execution_authorization'] and not report['b']['false_execution_authorizations'] else 'FAIL'
    (output/'results.json').write_text(json.dumps(report,indent=2)+'\n')
    (output/'rows.json').write_text(json.dumps({'a':a,'b':b},indent=2)+'\n')
    print(json.dumps({'status':report['status'],'a':report['a'],'b':report['b']},indent=2))
    return 0 if report['status']=='PASS' else 1
if __name__=='__main__':sys.exit(main())
