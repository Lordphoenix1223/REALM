"""Synthetic development-history data for checker contract tests only.

No execution, referee, native owner or qualification is claimed by this builder.
It cannot issue authority. Original real-run evidence/tests remain private.
"""
import coding_worker as codec


def text(value):
    return codec.encoded(value).decode()


def chain(items):
    previous = '0' * 64
    lines = []
    for sequence, item in enumerate(items):
        row = dict(item, sequence=sequence, previous=previous)
        previous = codec.digest(codec.encoded(row))
        lines.append(text(dict(row, sha256=previous)))
    return '\n'.join(lines) + '\n', previous


def make_fixture():
    baseline = {name:codec.digest(('TEST_ONLY_BASELINE:' + name).encode())
                for name in ('totals.py', 'report.py', 'test_totals.py')}
    task = {'contract':{'baseline':baseline}, 'worker_sha256':'a'*64}
    task['contract_sha256'] = codec.digest(codec.encoded(task['contract']))
    freeze = {'source_commit':'b'*40, 'definition_sha256':'c'*64,
              'criteria_pins':{'api':'d'*64, 'cli':'e'*64},
              'final_task_wrapper_sha256':codec.digest(codec.encoded(task))}
    project = codec.digest(codec.encoded(freeze))
    records, ledger, successful = [], [], []
    api_sources = {'totals.py':'TEST_ONLY_API_RESULT', 'test_totals.py':'TEST_ONLY_API_TEST'}
    for role, attempt, passed in [('api',1,False), ('api',2,True), ('cli',1,True)]:
        state = dict(baseline)
        session_id = f'TEST_ONLY_{role}_{attempt}'
        capture_start = 3 if role == 'cli' else 1
        worker_events = [{'event':{'contract':task['contract'],
            'contract_sha256':task['contract_sha256'], 'worker_sha256':task['worker_sha256']}}]
        session_events = [{'session':session_id, 'phase':'READY', 'data':{}}]
        writes = list(api_sources.items()) if role == 'cli' else []
        writes += (list(api_sources.items()) if role == 'api' and passed else
                   [('totals.py','TEST_ONLY_INCORRECT_API'), ('test_totals.py','TEST_ONLY_FAILURE_TEST')]
                   if role == 'api' else
                   [('report.py','TEST_ONLY_CLI_RESULT'), ('test_totals.py','TEST_ONLY_CLI_TEST')])
        for name, content in writes:
            action = {'tool':'write', 'path':name, 'text':content}
            reply = {'status':'TEST_ONLY_RECORDED_WRITE'}
            before = dict(state)
            state[name] = codec.digest(content.encode())
            worker_events.append({'event':{'request':action, 'result':reply,
                                          'before':before, 'after':dict(state)}})
            session_events.extend([
                {'session':session_id, 'phase':'DISPATCH_INTENT', 'data':{'action':action}},
                {'session':session_id, 'phase':'REPLY', 'data':{'result':reply}},
            ])
        worker_raw, worker_head = chain(worker_events)
        terminal = {'status':'PASS', 'owned_processes_closed':True}
        session_events.append({'session':session_id, 'phase':'CLOSED', 'data':terminal})
        session_raw, session_head = chain(session_events)
        session = {'session':session_id, 'journal_head':session_head, 'terminal':terminal,
                   'task_sha256':task['contract_sha256'], 'profile':'development-kernel-child',
                   'authority':'NONE', 'actual_vm':'NOT_RUN', 'qualification':'NOT_RUN',
                   'state':'CLOSED', 'failure':None}
        receipt = {'status':('PASS_API_SUBTASK' if role == 'api' else 'PASS_BOUNDED_PROPERTIES')
                   if passed else 'TEST_ONLY_FAILED_REFEREE',
                   'scope_sha256':freeze['criteria_pins'][role], 'authority':'NONE',
                   'subject':{name:{'sha256':value} for name,value in state.items()}}
        item = {'task':role, 'attempt':attempt, 'attempt_id':session_id, 'project_id':project,
                'source_commit':freeze['source_commit'], 'definition_pin':freeze['definition_sha256'],
                'task_sha256':task['contract_sha256'], 'criteria_pin':freeze['criteria_pins'][role],
                'status':'PASS' if passed else 'FAIL', 'authority':'NONE',
                'capture_start_sequence':capture_start, 'journal_head':worker_head,
                'referee_exit':0 if passed else 1,
                'session':{'id':session_id, 'journal_head':session_head, 'terminal':terminal}}
        start = dict(item, status='FAIL')
        ledger.extend([{'project':project,'phase':'BEGIN','item':start},
                       {'project':project,'phase':'BOUND','item':dict(start,session_id=session_id)},
                       {'project':project,'phase':'END','item':item}])
        records.append({'outcome':item, 'session':text(session), 'session_journal':session_raw,
                        'worker_journal':worker_raw, 'referee':text(receipt)})
        if passed:
            successful.append({'id':role, 'attempt':attempt, 'criteria_pin':item['criteria_pin'],
                               'receipt_json':text(receipt), 'depends_on':[] if role == 'api' else ['api']})
    body = {'schema':'realm.project-session-history.v1', 'project_id':project,
            'ledger':chain(ledger)[0], 'attempts':records, 'authority':'NONE',
            'project_freeze':freeze, 'task':task}
    return {'project_id':project, 'successful_tasks':successful,
            'metadata':{'fixture_class':'SYNTHETIC_NON_AUTHORIZING_HISTORY',
                        'attempt_history':body, 'attempt_history_sha256':codec.digest(codec.encoded(body)),
                        'failed_attempts_excluded':[{'task':'api','attempt':1}]}}
