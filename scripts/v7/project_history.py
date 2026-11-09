"""Pinned development attempt accounting; never execution authorization."""
import argparse
import json
import os
from pathlib import Path
import coding_worker as codec


def chain(raw):
    rows=[]; previous='0'*64
    for n,line in enumerate(raw.splitlines()):
        row=codec.parse(line); claimed=row.pop('sha256')
        if row['sequence']!=n or row['previous']!=previous or codec.digest(codec.encoded(row))!=claimed:
            raise ValueError('attempt/session journal chain differs')
        previous=claimed;rows.append(row)
    return rows,previous


class History:
    def __init__(self, root, project):
        self.project,self.head,self.count=project,'0'*64,0
        self.file=(root/'attempts.jsonl').open('xb',buffering=0)
    def append(self, phase, item):
        row={'sequence':self.count,'previous':self.head,'project':self.project,'phase':phase,'item':item}
        self.head=codec.digest(codec.encoded(row))
        self.file.write(codec.encoded({**row,'sha256':self.head})+b'\n');os.fsync(self.file.fileno());self.count+=1
    def close(self):
        if not self.file.closed:self.file.close()


def snapshot(root, project, attempts):
    records=[]
    for item in attempts:
        attempt=root/(item['task']+'-attempt-'+str(item['attempt']))
        def text(name):
            p=attempt/name
            return p.read_text() if p.is_file() else None
        records.append({'outcome':item,'session':text('session/result.json'),
            'session_journal':text('session/session.jsonl'),'worker_journal':text('session/worker/events.jsonl'),
            'referee':text('referee/result.json')})
    return {'schema':'realm.project-session-history.v1','project_id':project,'ledger':(root/'attempts.jsonl').read_text(),
            'attempts':records,'authority':'NONE',
            'project_freeze':codec.parse((root/'project-freeze.json').read_bytes()),
            'task':codec.parse((root/'frozen-final-task.json').read_bytes())}


def audit(body, expected_pin):
    if codec.digest(codec.encoded(body))!=expected_pin:raise ValueError('externally frozen history pin differs')
    if body['schema']!='realm.project-session-history.v1' or body['authority']!='NONE':raise ValueError('history schema differs')
    rows,head=chain(body['ledger']);pending={};ended=[];seen=set();passed=set();sessions=set();bindings={};partial_starts=set()
    freeze,task=body['project_freeze'],body['task']
    if codec.digest(codec.encoded(freeze))!=body['project_id'] or codec.digest(codec.encoded(task))!=freeze['final_task_wrapper_sha256']:
        raise ValueError('frozen project/task wrapper differs')
    for row in rows:
        if row['project']!=body['project_id']:raise ValueError('foreign project')
        item=row['item']; key=(item['task'],item['attempt']);identity=item['attempt_id']
        if (item['project_id']!=body['project_id'] or item['source_commit']!=freeze['source_commit']
            or item['definition_pin']!=freeze['definition_sha256'] or item['task_sha256']!=task['contract_sha256']
            or item['criteria_pin']!=freeze['criteria_pins'][item['task']]):raise ValueError('attempt task/policy/source binding differs')
        if item['task'] not in ('api','cli') or item['attempt'] not in (1,2):raise ValueError('attempt scope differs')
        if row['phase']=='BEGIN':
            if identity in seen or key in pending or any((x['task'],x['attempt'])==key for x in ended):raise ValueError('duplicate attempt')
            if item['task']=='cli' and 'api' not in passed:raise ValueError('incomplete dependency')
            previous=[x for x in ended if x['task']==item['task']]
            if item['attempt']!=len(previous)+1 or any(x['status']=='PASS' for x in previous):raise ValueError('retry ordering differs')
            seen.add(identity);pending[key]=identity
        elif row['phase']=='START_FAILED':
            if pending.get(key)!=identity or identity in bindings or not item.get('start_failed'):
                raise ValueError('invalid partial startup observation')
            bindings[identity]=item['session_id'];partial_starts.add(identity)
        elif row['phase']=='BOUND':
            if pending.get(key)!=identity or identity in bindings:raise ValueError('session binding without intent')
            bindings[identity]=item['session_id']
        elif row['phase']=='END':
            if pending.pop(key,None)!=identity:raise ValueError('missing attempt intent')
            if item['status'] not in ('PASS','FAIL','INTERRUPTED'):raise ValueError('invalid attempt status')
            ended.append(item)
            if item['status']=='PASS':passed.add(item['task'])
        else:raise ValueError('unknown attempt phase')
    if pending:raise ValueError('incomplete attempt closure')
    if ended!=[r['outcome'] for r in body['attempts']]:raise ValueError('terminal attempts omitted or altered')
    api_state=None
    for record in body['attempts']:
        item=record['outcome'];session=codec.parse(record['session']) if record['session'] else None
        if item['attempt_id'] in bindings and session is None:
            raise ValueError('bound session capture missing')
        if session:
            if session['session'] in sessions:raise ValueError('reused session')
            sessions.add(session['session']);journal,h=chain(record['session_journal'])
            if h!=session['journal_head'] or not journal or journal[-1]['phase']!='CLOSED':raise ValueError('session closure differs')
            if any(r['session']!=session['session'] for r in journal):raise ValueError('foreign session')
            if item['attempt_id'] in partial_starts and (item['status']=='PASS' or not item.get('start_failed')
                or any(r['phase'] in ('READY','DISPATCH_INTENT') for r in journal)):
                raise ValueError('partial startup promoted or mislabeled as ready')
            if (bindings.get(item['attempt_id'])!=session['session'] or item.get('session',{}).get('id')!=session['session']
                or item['session']['journal_head']!=h or item['session']['terminal']!=session['terminal']
                or journal[-1]['data']!=session['terminal'] or session['task_sha256']!=item['task_sha256']
                or session['profile']!='development-kernel-child' or session['authority']!='NONE'
                or session['actual_vm']!='NOT_RUN' or session['qualification']!='NOT_RUN'):
                raise ValueError('outcome/session task or closure binding differs')
        captured={};state=None;events=[];whead=None
        if session and any(r['phase']=='READY' for r in journal) and not record['worker_journal']:
            raise ValueError('failed or successful ready session lost Worker journal')
        if record['worker_journal']:
            events,whead=chain(record['worker_journal'])
            genesis=events[0]['event']
            if (genesis['contract_sha256']!=task['contract_sha256'] or genesis['worker_sha256']!=task['worker_sha256']
                or genesis['contract']!=task['contract']):raise ValueError('Worker task/source differs')
            dispatches=[]
            for frame in journal:
                if frame['phase']=='DISPATCH_INTENT':dispatches.append({'action':frame['data']['action'],'reply':None})
                elif frame['phase']=='REPLY':
                    if not dispatches or dispatches[-1]['reply'] is not None:raise ValueError('unbound session reply')
                    dispatches[-1]['reply']=frame['data']['result']
            if len(events)-1>len(dispatches):raise ValueError('Worker effect without session dispatch')
            for event,dispatch in zip(events[1:],dispatches):
                value=event['event']
                if 'refusal' in value:
                    if value['request_sha256']!=codec.digest(codec.encoded(dispatch['action'])+b'\n'):
                        raise ValueError('Worker refusal differs from session dispatch')
                    actual=value['refusal']
                else:
                    if value['request']!=dispatch['action']:raise ValueError('Worker request differs from original session')
                    actual=value['result']
                if dispatch['reply'] is not None and dispatch['reply']!=actual:raise ValueError('Worker reply differs from original session')
            if session['terminal']['status']=='PASS' and (len(events)-1!=len(dispatches) or any(d['reply'] is None for d in dispatches)):
                raise ValueError('closed session has incomplete captured exchange')
            state=dict(task['contract']['baseline'])
            for event in events[1:]:
                value=event['event']
                if 'refusal' in value:continue
                if value['before']!=state:raise ValueError('unexplained preceding effect')
                q=value['request']
                if q.get('tool')=='write':
                    if q['path'] not in state:raise ValueError('forbidden captured effect')
                    state[q['path']]=codec.digest(q['text'].encode())
                    if event['sequence']>=item.get('capture_start_sequence',10**9):captured[q['path']]=state[q['path']]
                if value['after']!=state:raise ValueError('unaccounted captured effect')
                if event['sequence']==item.get('capture_start_sequence',-1)-1 and item['task']=='cli' and api_state!=state:
                    raise ValueError('dependent state differs from verified API')
            if record['referee']:
                receipt=codec.parse(record['referee'])
                if receipt.get('subject') and any(receipt['subject'][n]['sha256']!=v for n,v in state.items()):
                    raise ValueError('failed or successful checker subject differs')
        if item['status']=='PASS':
            if (not session or session['state']!='CLOSED' or session['failure'] is not None
                or session['terminal']['status']!='PASS' or not session['terminal']['owned_processes_closed']
                or item.get('error') or item.get('referee_exit')!=0):raise ValueError('failed/incomplete execution promoted')
            receipt=codec.parse(record['referee']);status='PASS_API_SUBTASK' if item['task']=='api' else 'PASS_BOUNDED_PROPERTIES'
            if receipt['status']!=status or receipt['scope_sha256']!=item['criteria_pin'] or receipt['authority']!='NONE':raise ValueError('independent check differs')
            required={'totals.py','test_totals.py'} if item['task']=='api' else {'report.py','test_totals.py'}
            if set(captured)!=required or whead!=item['journal_head']:raise ValueError('captured task effects differ')
            if any(v!=receipt['subject'][name]['sha256'] for name,v in captured.items()):raise ValueError('checker subject differs')
            if item['task']=='api':api_state=dict(state)
    return {'status':'PASS_DEVELOPMENT_ATTEMPT_ACCOUNTING','authority':'NONE','attempts':len(ended),
            'failed_attempts':sum(x['status']!='PASS' for x in ended),'ledger_head':head,'session_count':len(sessions),'qualification':'NOT_RUN'}


def audit_procedure(procedure, expected_pin):
    body=procedure['metadata']['attempt_history']
    result=audit(body,expected_pin)
    if procedure['project_id']!=body['project_id']:
        raise ValueError('procedure/history project differs')
    for record in body['attempts']:
        if record['outcome'].get('session'):
            session=codec.parse(record['session'])
            if session['terminal']['owned_processes_closed'] is not True:
                raise ValueError('prior attempt process closure UNKNOWN; executable composition refused')
            frames,_=chain(record['session_journal'])
            effects,_=chain(record['worker_journal']) if record['worker_journal'] else ([],None)
            if sum(r['phase']=='DISPATCH_INTENT' for r in frames)!=max(0,len(effects)-1):
                raise ValueError('prior dispatched outcome UNKNOWN; executable composition refused')
    selected=procedure['successful_tasks']
    if [x['id'] for x in selected]!=['api','cli']:
        raise ValueError('exact successful task selectors required')
    passed={(r['outcome']['task'],r['outcome']['attempt']):r for r in body['attempts'] if r['outcome']['status']=='PASS'}
    for selector in selected:
        record=passed.get((selector['id'],selector['attempt']))
        if (record is None or selector['criteria_pin']!=record['outcome']['criteria_pin']
            or selector['receipt_json']!=record['referee']
            or selector['depends_on']!=([] if selector['id']=='api' else ['api'])):
            raise ValueError('successful selector lacks corresponding checked closed attempt')
    failed=[{'task':r['outcome']['task'],'attempt':r['outcome']['attempt']} for r in body['attempts'] if r['outcome']['status']!='PASS']
    if procedure['metadata']['failed_attempts_excluded']!=failed:
        raise ValueError('failed attempt selection differs')
    return result


def main():
    p=argparse.ArgumentParser(description=__doc__)
    s=p.add_mutually_exclusive_group(required=True);s.add_argument('--history',type=Path);s.add_argument('--extracted',type=Path);s.add_argument('--procedure',type=Path)
    p.add_argument('--expected-pin',required=True);a=p.parse_args()
    if a.procedure:
        print(json.dumps(audit_procedure(codec.parse(a.procedure.read_bytes()),a.expected_pin)));return
    if a.history:body=codec.parse(a.history.read_bytes())
    else:
        extracted=codec.parse(a.extracted.read_bytes());freeze=codec.parse(extracted['evidence']['pre_agent_freeze'])
        procedure=codec.parse(freeze['successful_procedure'])
        print(json.dumps(audit_procedure(procedure,a.expected_pin)));return
    print(json.dumps(audit(body,a.expected_pin)))

if __name__=='__main__':main()
