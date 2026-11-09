"""Two dependent development subtasks, called only by the existing entrypoint.

No native admission, production publication or protected application authority.
"""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import uuid
import project_history
from types import SimpleNamespace

import coding_worker as worker
import coding_task_verifier as referee
import live_codex_planner
from run_development_vertical import encoded, sha, write, snapshot

REQUEST = 'Build a Unicode run-length tool: implement and test the summarize API, then add a JSON stdin/stdout CLI that uses it.'
DEFINITION_PIN = 'dff8541ec979eade405f0c3049f1aa2febbf4e3839cd5c4314930aa3eea654c8'


def decompose(request):
    normalize = lambda x: ' '.join(x.casefold().split()).rstrip('.')
    if normalize(request) != normalize(REQUEST):
        raise ValueError('REFUSE: unsupported or ambiguous request; supported request: '+REQUEST)
    return [('api', (), ('totals.py', 'test_totals.py')),
            ('cli', ('api',), ('report.py', 'test_totals.py'))]


def run_project(args):
    source = Path(__file__).resolve().parents[2]
    tasks = decompose(args.request)  # Before filesystem/model/build effects.
    if subprocess.check_output(['git', 'status', '--porcelain', '--', 'Cargo.toml', 'Cargo.lock', 'crates', 'scripts'], cwd=source):
        raise ValueError('freeze source before execution')
    root = args.output.resolve(); root.mkdir(mode=0o700)
    commit = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=source, text=True).strip()
    records = []; attempts = []; winners = {}; phase = 'freeze'
    history = None
    args.session_api = True  # One controller execution entry point.
    def run(label, argv, expected=0, timeout=180):
        argv = [str(x) for x in argv]
        r = subprocess.run(argv, cwd=source, capture_output=True, timeout=timeout)
        write(root/(label+'.stdout'), r.stdout); write(root/(label+'.stderr'), r.stderr)
        records.append({'stage': label, 'argv': argv, 'exit': r.returncode})
        if expected is not None and r.returncode != expected:
            raise ValueError(label+' failed; inspect original stderr')
        return r
    def record(name, value):
        write(root/name, encoded(value))
    def check_attempt(task_id, w, attempt):
        argv = [sys.executable,'-B',source/'scripts/v7/coding_task_verifier.py','check-api' if task_id=='api' else 'check',
                '--candidate',w.candidate,'--output',attempt/'referee','--scope-sha256',pins[task_id],'--seed','20261031',
                '--development-task',definition,'--development-task-sha256',DEFINITION_PIN]
        result = subprocess.run([str(x) for x in argv], cwd=source, capture_output=True, timeout=180)
        write(attempt/'referee.stdout',result.stdout); write(attempt/'referee.stderr',result.stderr)
        record_name = attempt/'referee/result.json'
        receipt = json.loads(record_name.read_bytes()) if record_name.exists() else None
        return result, receipt, record_name
    try:
        definition = source/'scripts/v7/fresh_tasks/unicode-runs.definition.json'
        worker.configure_development_task(definition, DEFINITION_PIN)
        criteria = {'api': referee.api_scope(), 'cli': referee.describe()}
        pins = {k: worker.digest(worker.encoded(v)) for k, v in criteria.items()}
        identities = {str(p): sha(p.read_bytes()) for p in [Path(__file__), Path(worker.__file__), Path(referee.__file__), Path(live_codex_planner.__file__), source/'scripts/v7/run_development_vertical.py', source/'scripts/v7/verify_coding_development.py', source/'scripts/v7/vm_session.py', source/'scripts/v7/vm_session_host.py', source/'scripts/v7/project_history.py', definition]}
        if args.session_api:
            identities.update({str(source/'scripts/v7'/n):sha((source/'scripts/v7'/n).read_bytes())
                               for n in ('vm_session.py','vm_session_host.py','host_planned_coding.py')})
        frozen = {'schema': 'realm.two-subtask-development.v1', 'source_commit': commit,
                  'request': args.request, 'request_sha256': sha(args.request.encode()),
                  'definition_sha256': DEFINITION_PIN, 'criteria': criteria, 'criteria_pins': pins,
                  'tasks': tasks, 'identities': identities,
                  'session_profile':'development-kernel-child' if args.session_api else 'direct-development-worker',
                  'budgets':{'session_seconds_per_attempt':300 if args.session_api else None,'attempts_per_task':2,'planner_seconds_per_attempt':args.planner_timeout,
                             'referee_seconds_per_attempt':180,'candidate_seconds_per_process':3,
                             'candidate_output_bytes_per_stream':worker.MAX_BYTES}, 'nonce': os.urandom(32).hex(), 'authority': 'NONE'}
        intake = {'contract':worker.contract(),'contract_sha256':worker.digest(worker.encoded(worker.contract())),
                  'worker_sha256':sha(Path(worker.__file__).read_bytes()),
                  'checker_sha256':sha(Path(referee.__file__).read_bytes()),'checker_scope_sha256':pins['cli']}
        task = root/'frozen-final-task.json'; record(task.name, intake)
        task_pin = sha(encoded(intake)); identities[str(task)] = task_pin
        frozen['final_task_wrapper_sha256'] = task_pin
        project_id = sha(encoded(frozen)); record('project-freeze.json', frozen)
        history = project_history.History(root, project_id)
        phase = 'build'
        env = dict(os.environ, CARGO_TARGET_DIR=str(args.target.resolve()), CARGO_INCREMENTAL='0', CARGO_PROFILE_DEV_DEBUG='0', CARGO_BUILD_JOBS='2')
        command = ['cargo', 'build', '--offline', '--locked', '-p', 'realm-cli', '-p', 'realm-artifact', '--bin', 'realm', '--bin', 'realm-stage8-broker', '--features', 'realm-cli/development-executor,realm-artifact/receiver-fixtures']
        r = subprocess.run(command, cwd=source, env=env, capture_output=True, timeout=240)
        write(root/'build.stdout', r.stdout); write(root/'build.stderr', r.stderr)
        records.append({'stage':'build','argv':command,'exit':r.returncode})
        if r.returncode: raise ValueError('development executor build failed')
        realm = args.target.resolve()/'debug/realm'
        libs = list((args.target.resolve()/'debug/deps').glob('libblake3-*.rlib'))
        if len(libs) != 1: raise ValueError('ambiguous hasher dependency')
        hasher = root/'hash-helper'
        run('build-hasher', ['rustc','--edition=2024',source/'scripts/v6/runtime_recovery_blake3.rs','--extern','blake3='+str(libs[0]),'-L','dependency='+str(libs[0].parent),'-o',hasher])
        def b3(raw): return subprocess.check_output([hasher], input=raw, timeout=10).decode().strip()
        identities[str(realm)] = sha(realm.read_bytes())
        stage8_broker = args.target.resolve()/'debug/realm-stage8-broker'
        identities[str(stage8_broker)] = sha(stage8_broker.read_bytes())
        for name in ('stage8_enforcement.py', 'verify_stage8_state.py'):
            path = source/'scripts/v7'/name
            identities[str(path)] = sha(path.read_bytes())
        identities[str(hasher)] = sha(hasher.read_bytes())
        record('runtime-identities.json', {'source_commit':commit,'identities':identities,'authority':'NONE'})
        for task_id, dependencies, writable in tasks:
            phase = task_id; previous_feedback = None
            for number in (1, 2):
                attempt = root/(task_id+'-attempt-'+str(number)); attempt.mkdir(mode=0o700)
                w = session = None
                item = {'task':task_id,'attempt':number,'attempt_id':uuid.uuid4().hex,
                        'project_id':project_id,'criteria_pin':pins[task_id],
                        'task_sha256':intake['contract_sha256'],'source_commit':commit,
                        'definition_pin':DEFINITION_PIN,'status':'FAIL','authority':'NONE'}
                history.append('BEGIN',dict(item))
                candidate_winner = None
                try:
                    if args.session_api:
                        from vm_session import Session, SessionRequest
                        session = Session.start(SessionRequest('development-kernel-child',
                            worker.digest(worker.encoded(worker.contract())), 300,
                            development_task=definition, development_task_sha256=DEFINITION_PIN), attempt/'session')
                        history.append('BOUND',dict(item,session_id=session.collect()['session']))
                        worker_root = Path(session.collect()['worker_records'])
                        candidate = worker_root/'candidate'
                        def tree():
                            fd = os.open(candidate, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
                            try:
                                if set(os.listdir(fd)) != set(worker.FILES): raise ValueError('candidate scope differs')
                                return {n:worker.digest(worker.regular_read(fd,n)) for n in worker.FILES}
                            finally:
                                os.close(fd)
                        w = SimpleNamespace(root=worker_root, candidate=candidate, request=session.execute,
                                            tree=tree, close=session.close)
                    else:
                        raise ValueError('project requires the session facade')
                    if dependencies:
                        for name, data in winners['api']['sources'].items():
                            w.request({'tool':'write','path':name,'text':data.decode()})
                    before = w.tree(); inputs = {n:b3((w.candidate/n).read_bytes()) for n in worker.FILES}
                    sb = worker.Sandbox(w.candidate)
                    conformance = worker.conformance(sb, w.root/'protected-sentinel')
                    write(attempt/'environment.json', encoded({'mode':'DEVELOPMENT_SANDBOX','qualified_vm':'NOT_RUN','sandbox':sb.profile,'conformance':conformance}))
                    first_sequence = len((w.root/'events.jsonl').read_bytes().splitlines())
                    item['capture_start_sequence'] = first_sequence
                    spec = json.loads(definition.read_bytes())['description'].split(' Implement summarize')[0]
                    description = ('API subtask: implement summarize(value) returning the specified dictionary and raising ValueError for invalid values. '+spec+' Change totals.py and test_totals.py only. Test the pure API; report.py is not implemented yet.' if task_id=='api' else
                                   'Dependent CLI subtask: preserve the read-only verified totals.py byte-for-byte. '+spec+' Implement report.py reading JSON stdin and printing summarize(value), exit2 on invalid input/JSON. Change report.py and test_totals.py; tests must change and may test CLI in-process. No subprocesses.')
                    view = SimpleNamespace(FILES=writable, DESCRIPTION=description, BASELINE={n:worker.BASELINE[n] for n in writable},
                        MAX_BYTES=worker.MAX_BYTES, encoded=worker.encoded, parse=worker.parse,
                        READ_ONLY_DEPENDENCIES={'totals.py':winners['api']['sources']['totals.py'].decode()} if dependencies else {})
                    feedback = [] if previous_feedback is None else [{'action':{'tool':'independent-referee'},'response':previous_feedback}]
                    actions = live_codex_planner.generate(view, attempt, feedback, 1, args.planner_timeout, candidate_root=w.candidate)
                    for action in actions:
                        if action['tool']=='write':
                            if action['path'] not in writable: raise ValueError('write outside frozen subtask scope')
                            if sha(action['text'].encode()) == before[action['path']]: raise ValueError('each subtask file must change')
                            reply = w.request(action)
                            if reply.get('written') != action['path']:
                                raise ValueError('session did not acknowledge permitted write')
                        elif action != {'tool':'check'} and action != {'tool':'finish'}:
                            raise ValueError('unsupported planner action')
                    if session is not None:
                        record_path = attempt/'session-before-close.json'
                        write(record_path, encoded(session.collect()))
                        terminal = session.close()
                        if (terminal['terminal']['status'] != 'PASS' or terminal['failure'] is not None
                                or terminal['authority'] != 'NONE' or terminal['actual_vm'] != 'NOT_RUN'):
                            raise ValueError('subtask development session closure incomplete')
                        item['session'] = {'id':terminal['session'],'profile':terminal['profile'],
                            'journal_head':terminal['journal_head'],'terminal':terminal['terminal'],
                            'task_finished':terminal['task_finished'],'qualification':terminal['qualification']}
                    if dependencies and w.tree()['totals.py'] != winners['api']['sha256']['totals.py']:
                        raise ValueError('verified API dependency changed')
                    result,receipt,record_name=check_attempt(task_id,w,attempt)
                    item['referee_exit']=result.returncode
                    expected_status = 'PASS_API_SUBTASK' if task_id=='api' else 'PASS_BOUNDED_PROPERTIES'
                    if result.returncode or receipt is None or receipt['status']!=expected_status:
                        raise ValueError('independent referee failed: '+result.stderr.decode(errors='replace')[-4000:])
                    rows = [json.loads(l) for l in (w.root/'events.jsonl').read_bytes().splitlines()]
                    captured = {}
                    for row in rows:
                        if row['sequence'] < first_sequence: continue
                        q = row['event'].get('request',{})
                        if q.get('tool')=='write': captured[q['path']]=q['text'].encode()
                    if set(captured)!=set(writable): raise ValueError('successful captured write scope differs')
                    for n, raw in captured.items():
                        if sha(raw)!=receipt['subject'][n]['sha256'] or raw!=(w.candidate/n).read_bytes():
                            raise ValueError('referee subject differs from actual captured writes')
                    item.update(status='PASS',journal_head=rows[-1]['sha256'],criteria_pin=pins[task_id])
                    candidate_winner={'sources':captured,'sha256':w.tree(),'task':{
                        'id':task_id,'attempt':number,'depends_on':list(dependencies),'criteria_pin':pins[task_id],
                        'receipt_json':record_name.read_text(),'receipt_blake3':b3(record_name.read_bytes()),
                        'inputs':inputs,'outputs':{n:b3(raw) for n,raw in captured.items()}}}
                except BaseException as error:
                    item['error']=repr(error)
                    if isinstance(error,(KeyboardInterrupt,SystemExit)):
                        item['status']='INTERRUPTED';item['interrupted']=True
                    previous_feedback={'independent_referee_failure':repr(error),
                                       'previous_source':{n:(w.candidate/n).read_text() for n in writable if (w.candidate/n).is_file()} if w is not None else {}}
                finally:
                    if session is not None:
                        try:
                            terminal=session.close()
                            item['session']={'id':terminal['session'],'terminal':terminal['terminal'],
                                'journal_head':terminal['journal_head'],'qualification':terminal['qualification']}
                            if terminal['terminal']['status']!='PASS' or terminal['failure'] is not None:
                                item['status']='FAIL';item['error']=item.get('error','incomplete session closure')
                        except BaseException as closure_error:
                            item['status']='FAIL';item['error']=item.get('error',repr(closure_error))
                    if w is not None and 'referee_exit' not in item:
                        try:
                            failed_check,_,_=check_attempt(task_id,w,attempt)
                            item['referee_exit']=failed_check.returncode
                        except BaseException as checker_error:
                            item['independent_check']='NOT_RUN: '+repr(checker_error)
                    if session is None and (attempt/'session/result.json').is_file():
                        # start() can fail after allocating a real owned host.
                        # Observe its retained record; never fabricate READY/BOUND.
                        partial=worker.parse((attempt/'session/result.json').read_bytes())
                        item['start_failed']=True
                        item['session']={'id':partial['session'],'terminal':partial['terminal'],
                            'journal_head':partial['journal_head'],'qualification':partial['qualification']}
                        item['independent_check']='NOT_RUN: no usable session handle'
                        history.append('START_FAILED',dict(item,session_id=partial['session']))
                    write(attempt/'OUTCOME.json',encoded(item))
                    history.append('END',dict(item));attempts.append(item)
                if item.get('interrupted'):raise InterruptedError('attempt interrupted; no automatic retry')
                if item['status']=='PASS':
                    winners[task_id]=candidate_winner
                    break
            if task_id not in winners: raise ValueError('bounded attempts exhausted for '+task_id)
        phase = 'audit-attempt-history'
        history.close()
        history_body=project_history.snapshot(root,project_id,attempts)
        history_pin=sha(encoded(history_body))
        record('attempt-history.json',history_body)
        run('attempt-history-audit',[sys.executable,'-B',source/'scripts/v7/project_history.py',
            '--history',root/'attempt-history.json','--expected-pin',history_pin])
        phase = 'compose'
        files = {'totals.py':winners['api']['sources']['totals.py'], **winners['cli']['sources']}
        operations = [{'kind':'create-file','index':i,'path':n,'content_blake3':b3(files[n]),'bytes':len(files[n]),
                       'mode':0o600,'requires_completed':i,'source_task':'api' if i==0 else 'cli'} for i,n in enumerate(worker.FILES)]
        procedure={'schema':'realm.development-successful-procedure.v1','authority':'NONE','project_id':project_id,
                   'precondition':'fresh-empty-private-directory','commands':[],'network':False,'validation':['ordered-current-filesystem','independent-api-and-cli'],
                   'successful_tasks':[winners[k]['task'] for k in ('api','cli')], 'operations':operations,
                   'expected_files':{n:b3(v) for n,v in files.items()},
                   'metadata':{'attempt_history':history_body,'attempt_history_sha256':history_pin,'source_commit':commit,'request_sha256':sha(args.request.encode()),'definition_sha256':DEFINITION_PIN,
                               'inputs':'JSON values; Python standard library only','expected':'verified API and CLI finite-case obligations',
                               'superseded_excluded':['api:test_totals.py'],
                               'failed_attempts_excluded':[{'task':x['task'],'attempt':x['attempt']} for x in attempts if x['status']!='PASS']}}
        record('successful-procedure.json',procedure);proc_pin=b3(encoded(procedure))
        run('procedure-attempt-history-audit',[sys.executable,'-B',source/'scripts/v7/project_history.py',
            '--procedure',root/'successful-procedure.json','--expected-pin',history_pin])
        actions=[{'tool':'write','path':n,'text':files[n].decode()} for n in worker.FILES]+[{'tool':'check'},{'tool':'finish'}]
        record('successful-actions.json',actions)
        phase='execute-successful-procedure'
        run('procedure-capture',[sys.executable,'-B',source/'scripts/v7/run_development_vertical.py','--output',root/'final-capture',
            '--task',task,'--task-sha256',task_pin,'--development-task',definition,'--development-task-sha256',DEFINITION_PIN,
            '--actions',root/'successful-actions.json','--successful-procedure',root/'successful-procedure.json','--successful-procedure-pin',proc_pin,
            '--development-executor','--target',args.target.resolve(),'--verify-integrated-interfaces'] + (['--session-api'] if args.session_api else []),timeout=300)
        final=root/'final-capture'; r=json.loads((final/'RESULT.json').read_bytes());artifact=final/'capture.realm'
        epin=next(x['argv'][-1] for x in r['stages'] if x['stage']=='receiver')
        run('receiver-attempt-history-audit',[sys.executable,'-B',source/'scripts/v7/project_history.py',
            '--extracted',final/'receiver-extract.stdout','--expected-pin',history_pin])
        common=[artifact,r['artifact_blake3'],final/'expectations.json',epin,proc_pin]
        def mechanics(label, verb, dest, *tail, expected=0, data=common):
            return run(label,[realm,'transfer',verb,*data,dest,*tail],expected=expected)
        phase='stage8-enforcement'
        from stage8_enforcement import apply_development_procedure
        stage8 = apply_development_procedure(stage8_broker, artifact, r['artifact_blake3'],
            final/'expectations.json', epin, root/'successful-procedure.json', proc_pin, root/'stage8', attempt_history_pin=history_pin)
        destination, state = Path(stage8['destination']), Path(stage8['state'])
        phase='final-verification'
        run('final-semantic-referee',[sys.executable,'-B',source/'scripts/v7/coding_task_verifier.py','check','--candidate',destination,
            '--output',root/'final-referee','--scope-sha256',pins['cli'],'--seed','20261031','--development-task',definition,'--development-task-sha256',DEFINITION_PIN])
        # The legacy mechanics commands remain refusal controls only, not the
        # successful final executor. Stage8 owns application and verification.
        control_destination=root/'legacy-control-destination';control_destination.mkdir(mode=0o700)
        control_plan=json.loads(mechanics('legacy-control-plan','plan-development-procedure',control_destination).stdout)['result']
        approval=control_plan['approval_id']
        # Real proposals to the same constrained executor; every denial retained.
        phase='negative-controls'; negatives=[]
        def denied(label, proposal):
            bad=json.loads(encoded(procedure));proposal(bad)
            body=json.loads((final/'payload.json').read_bytes());freeze=json.loads(body['evidence']['pre_agent_freeze']);freeze['successful_procedure']=encoded(bad).decode();body['evidence']['pre_agent_freeze']=encoded(freeze).decode()
            path=root/(label+'.payload.json');write(path,encoded(body));bad_artifact=root/(label+'.realm')
            run(label+'-pack',[realm,'artifact','pack-development-coding',path,final/'expectations.json',b3(encoded(body)),epin,bad_artifact])
            guard=root/(label+'-destination');guard.mkdir(mode=0o700);before=snapshot(guard)
            rr=mechanics(label,'plan-development-procedure',guard,expected=1,data=[bad_artifact,b3(bad_artifact.read_bytes()),final/'expectations.json',epin,b3(encoded(bad))])
            if rr.stdout or snapshot(guard)!=before: raise ValueError('negative control acquired effects '+label)
            negatives.append(label)
        denied('extra-write',lambda p:p['operations'].append(dict(p['operations'][0],path='extra.py')))
        denied('unauthorized-command',lambda p:p['operations'][0].update(kind='exec'))
        denied('unauthorized-network',lambda p:p.update(network=True))
        denied('action-reordering',lambda p:p['operations'].reverse())
        denied('tampered-instruction',lambda p:p['operations'][0].update(content_blake3='0'*64))
        denied('failed-receipt',lambda p:p['successful_tasks'][0].update(receipt_json='{}',receipt_blake3=b3(b'{}')))
        # Changed destination and unexpected final entries are actual filesystem controls.
        other=root/'changed-destination';other.mkdir(mode=0o700);otherstate=root/'other-state';otherstate.mkdir(mode=0o700)
        mechanics('changed-destination','apply-development-procedure',other,otherstate,approval,expected=1)
        if list(other.iterdir()): raise ValueError('changed destination accepted')
        nd=root/'unexpected-destination';nd.mkdir(mode=0o700);ns=root/'unexpected-state';ns.mkdir(mode=0o700)
        np=json.loads(mechanics('unexpected-plan','plan-development-procedure',nd).stdout)['result']
        mechanics('unexpected-apply','apply-development-procedure',nd,ns,np['approval_id'])
        write(nd/'unlisted.py',b'EXPLICIT NEGATIVE-CONTROL INJECTION\n')
        mechanics('unexpected-effect','verify-development-procedure',nd,ns,expected=1)
        negatives += ['changed-destination','unexpected-effect']
        # Actual wrong candidate -> actual independent refusal, never a claimed natural retry.
        nw = worker.Worker(root/'controlled-bad-api-worker', worker.digest(worker.encoded(worker.contract())))
        try:
            nw.request({'tool':'write','path':'totals.py','text':'def summarize(value):\n    return None  # EXPLICIT NEGATIVE CONTROL\n'})
            nw.request({'tool':'write','path':'test_totals.py','text':'# EXPLICIT NEGATIVE CONTROL\nassert True\n'})
            run('controlled-bad-api-referee',[sys.executable,'-B',source/'scripts/v7/coding_task_verifier.py','check-api',
                '--candidate',nw.candidate,'--output',root/'controlled-bad-api-referee','--scope-sha256',pins['api'],'--seed','20261031',
                '--development-task',definition,'--development-task-sha256',DEFINITION_PIN],expected=2)
            negatives.append('controlled-invalid-api-NOT_A_NATURAL_RETRY')
        finally:
            nw.close()
        independent_command = [sys.executable,'-B',source/'scripts/v7/verify_stage8_state.py',root/'stage8/frozen.realm',destination,state,stage8_broker]
        run('stage8-independent-after-controls', independent_command)
        for p,h in identities.items():
            if sha(Path(p).read_bytes())!=h: raise ValueError('executed controller/verifier source changed')
        result={'status':'PASS_DEVELOPMENT_TWO_SUBTASK_PROCEDURE','development_completed':True,'authority':'NONE',
                'source_commit':commit,'project_id':project_id,'attempts':attempts,'execution_entrypoint':'vm_session.Session','attempt_history_sha256':history_pin,'artifact':str(artifact),
                'artifact_sha256':sha(artifact.read_bytes()),'procedure_blake3':proc_pin,'destination':str(destination),
                'negative_controls':negatives,'qualified_vm':'NOT_RUN','production_application':'NOT_RUN',
                'executor':'STAGE8_SANDBOXED_EXACT_REQUEST_BROKER','stage8':stage8,
                'session_api':args.session_api,'session_profile':'development-kernel-child' if args.session_api else None,
                'stages':{str(i):('PARTIAL' if i in (2,3) else 'PASS') for i in range(1,10)},
                'boundaries':['Seatbelt development sandbox; planner outside','same-host user authority, no native custody',
                              'explicit disposable approval, no production grant or ACCEPT'], 'commands':records}
    except BaseException as error:
        result={'status':'INCOMPLETE','development_completed':False,'authority':'NONE','failed_stage':phase,
                'error':repr(error),'source_commit':commit,'attempts':attempts,'commands':records}
    if history is not None:
        history.close()
        if not (root/'attempt-history.json').exists():
            record('attempt-history.json',project_history.snapshot(root,project_id,attempts))
    record('PROJECT_RESULT.json',result)
    return result
