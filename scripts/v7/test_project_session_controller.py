"""Actual local controller controls with clearly scripted planner faults.

No model solves in these controls; normal fresh AI execution is run separately.
Each scenario uses the existing controller, real Session/Worker/referee and
original producer/receiver/disposable executor. No native/production authority.
"""
import dataclasses
import importlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import coding_worker as worker
import development_project as project
import project_history
from vm_session import Session

SOURCE=Path(__file__).resolve().parents[2]
TARGET=Path(os.environ.get('REALM_PROJECT_CONTROL_TARGET','/private/tmp/realm-project-session-control-target'))
ROOT=Path(os.environ.get('REALM_PROJECT_CONTROL_ROOT') or tempfile.mkdtemp(prefix='realm-project-controller-controls-',dir='/private/tmp'))
ROOT.mkdir(parents=True,exist_ok=True)


def arguments(output):
    return SimpleNamespace(request=project.REQUEST,output=output,target=TARGET,session_api=True,planner_timeout=5)


def proposals(task):
    # Reuse actual PR81 model-produced sources only as scripted control inputs.
    p=SOURCE/'evidence/v7/two-task-sessions-20261031/run001'/('api-attempt-1' if task=='api' else 'cli-attempt-1')/'planner-01/answer.json'
    return [{'tool':'write','path':name,'text':text} for name,text in worker.parse(p.read_bytes())['files'].items()]


class ControllerFailures(unittest.TestCase):
    def tearDown(self):importlib.reload(worker)

    def scenario(self, name, planner, *, short=False):
        root=ROOT/name
        real_start=Session.start
        def start(request,*a,**kw):
            if short and (short is True or type(short) is int or not self.started):
                seconds=3 if short in (3,'first-active') else 1
                request=dataclasses.replace(request,lifetime_seconds=seconds)
            session=real_start(request,*a,**kw);self.started.append(session);return session
        self.started=[]
        with patch.object(Session,'start',side_effect=start),patch.object(project.live_codex_planner,'generate',side_effect=planner):
            result=project.run_project(arguments(root))
        self.assertEqual(result['authority'],'NONE')
        return result,root

    def history(self,root):
        body=worker.parse((root/'attempt-history.json').read_bytes())
        result=project_history.audit(body,worker.digest(worker.encoded(body)))
        return body,result

    def test_controlled_failed_referee_retries_in_fresh_session(self):
        count=0
        def planner(view,run,*a,**kw):
            nonlocal count
            task='api' if 'api-attempt' in str(run) else 'cli'
            actions=proposals(task)
            if task=='api':
                count+=1
                if count==1:
                    for action in actions:
                        if action['path']=='totals.py':
                            action['text']="def summarize(value):\n    return 'EXPLICIT_NEGATIVE_CONTROL'\n"
            return actions
        result,root=self.scenario('controlled-retry',planner)
        self.assertTrue(result['development_completed'],result)
        self.assertEqual([a['status'] for a in result['attempts']],['FAIL','PASS','PASS'])
        failed=root/'api-attempt-1'
        self.assertTrue((failed/'referee/result.json').is_file())
        writes=[worker.parse(line)['event'].get('request',{}) for line in (failed/'session/worker/events.jsonl').read_bytes().splitlines()]
        self.assertEqual({q['path'] for q in writes if q.get('tool')=='write'},{'totals.py','test_totals.py'})
        self.assertEqual(len({a['session']['id'] for a in result['attempts']}),3)
        body,accounting=self.history(root);self.assertEqual(accounting['failed_attempts'],1)
        final=worker.parse((root/'final-capture/RESULT.json').read_bytes())
        self.assertEqual(final['receiver_decision'],'INCOMPLETE');self.assertFalse(final['application_dispatched'])
        self.assertTrue(final['protected_destination_unchanged'])
        procedure=worker.parse((root/'successful-procedure.json').read_bytes())
        project_history.audit_procedure(procedure,worker.digest(worker.encoded(body)))
        empty=worker.parse(worker.encoded(procedure));empty['metadata']['attempt_history']['attempts']=[]
        empty['metadata']['attempt_history']['ledger']=''
        with self.assertRaises(ValueError):
            project_history.audit_procedure(empty,worker.digest(worker.encoded(empty['metadata']['attempt_history'])))
        # Logical omissions are rejected even if a test recomputes its own pin.
        bad=worker.parse(worker.encoded(body));bad['attempts'].pop(0)
        with self.assertRaises(ValueError):project_history.audit(bad,worker.digest(worker.encoded(bad)))
        bad=worker.parse(worker.encoded(body));bad['ledger']=bad['ledger'].splitlines()[0]+'\n'
        with self.assertRaises(ValueError):project_history.audit(bad,worker.digest(worker.encoded(bad)))
        bad=worker.parse(worker.encoded(body));bad['attempts'][0]['session']=None
        bad['attempts'][0]['session_journal']=None
        with self.assertRaises(ValueError):project_history.audit(bad,worker.digest(worker.encoded(bad)))
        bad=worker.parse(worker.encoded(body));bad['attempts'][0]['worker_journal']=None
        with self.assertRaises(ValueError):project_history.audit(bad,worker.digest(worker.encoded(bad)))
        bad=worker.parse(worker.encoded(body));bad['attempts'][0]['session']=body['attempts'][1]['session']
        bad['attempts'][0]['session_journal']=body['attempts'][1]['session_journal']
        with self.assertRaises(ValueError):project_history.audit(bad,worker.digest(worker.encoded(bad)))
        bad=worker.parse(worker.encoded(body));bad['attempts'][0]['worker_journal']=body['attempts'][1]['worker_journal']
        with self.assertRaises(ValueError):project_history.audit(bad,worker.digest(worker.encoded(bad)))
        bad=worker.parse(worker.encoded(body));bad['attempts'][0]['outcome']['status']='PASS'
        with self.assertRaises(ValueError):project_history.audit(bad,worker.digest(worker.encoded(bad)))

    def test_forbidden_actions_exhaust_budget_without_artifact(self):
        result,root=self.scenario('forbidden',lambda *a,**kw:[{'tool':'shell','command':'id'}])
        self.assertFalse(result['development_completed']);self.assertEqual(len(result['attempts']),2)
        self.assertTrue(all(a['status']=='FAIL' and a['referee_exit']!=0 for a in result['attempts']))
        self.history(root);self.assertFalse((root/'final-capture').exists())

    def test_real_worker_crash_is_retained(self):
        def crash(*a,**kw):
            self.started[-1].child.kill();self.started[-1].child.wait(timeout=5)
            return proposals('api')
        result,root=self.scenario('worker-crash',crash)
        self.assertFalse(result['development_completed'])
        self.assertTrue(all(a['session']['terminal']['status']=='INCOMPLETE' for a in result['attempts']))
        self.history(root)

    def test_absolute_timeout_is_not_task_success(self):
        def wait(*a,**kw):time.sleep(1.3);return proposals('api')
        result,root=self.scenario('timeout',wait,short=True)
        self.assertFalse(result['development_completed'])
        self.assertTrue(all(a['status']=='FAIL' for a in result['attempts']))
        self.history(root)

    def test_interruption_is_recorded_and_never_retried(self):
        def interrupt(*a,**kw):raise KeyboardInterrupt('EXPLICIT DEVELOPMENT INTERRUPTION CONTROL')
        result,root=self.scenario('interrupt',interrupt)
        self.assertFalse(result['development_completed']);self.assertEqual(len(result['attempts']),1)
        self.assertTrue(result['attempts'][0]['interrupted']);self.history(root)

    def test_active_check_timeout_retains_incomplete_closure(self):
        def active(*a,**kw):
            s=self.started[-1]
            s.execute({'tool':'write','path':'test_totals.py','text':'import time\ntime.sleep(30)\n'})
            s.execute({'tool':'check'})
            return []
        result,root=self.scenario('incomplete-check',active,short=3)
        self.assertFalse(result['development_completed'])
        active=[]
        for outcome in result['attempts']:
            path=root/('api-attempt-'+str(outcome['attempt']))/'session/session.jsonl'
            if path.exists() and any(worker.parse(line)['phase']=='DISPATCH_INTENT' and
                    worker.parse(line)['data'].get('action',{}).get('tool')=='check'
                    for line in path.read_bytes().splitlines()):
                active.append(outcome)
        self.assertTrue(active,'NOT_RUN: startup failed before any actual check dispatch')
        self.assertTrue(all(a['session']['terminal']['status']=='INCOMPLETE' for a in active))
        self.history(root)

    def test_unknown_failed_closure_blocks_later_successful_composition(self):
        first=True
        def planner(view,run,*a,**kw):
            nonlocal first
            if first:
                first=False
                s=self.started[-1]
                s.execute({'tool':'write','path':'test_totals.py','text':'import time\ntime.sleep(30)\n'})
                s.execute({'tool':'check'})
            return proposals('api' if 'api-attempt' in str(run) else 'cli')
        result,root=self.scenario('unknown-then-success',planner,short='first-active')
        self.assertFalse(result['development_completed'])
        self.assertEqual([a['status'] for a in result['attempts']],['FAIL','PASS','PASS'])
        self.assertFalse(result['attempts'][0]['session']['terminal']['owned_processes_closed'])
        self.assertFalse((root/'final-capture').exists())
        self.assertFalse((root/'destination').exists())
        self.history(root)  # Diagnostic history is retained, not executable success.

    def test_partial_start_failure_keeps_original_identity_without_ready(self):
        real_popen=subprocess.Popen
        def delayed(*args,**kwargs):
            child=real_popen(*args,**kwargs)
            command=args[0] if args else kwargs.get('args',[])
            if any(str(x).endswith('/vm_session_host.py') for x in command):
                time.sleep(1.3)  # Real host deadline passes before caller reads READY.
            return child
        with patch('vm_session.subprocess.Popen',side_effect=delayed):
            result,root=self.scenario('partial-start',lambda *a,**kw:proposals('api'),short=True)
        self.assertFalse(result['development_completed'])
        self.assertEqual(len(result['attempts']),2)
        for item in result['attempts']:
            self.assertTrue(item['start_failed'])
            self.assertEqual(item['status'],'FAIL')
            self.assertIn('NOT_RUN',item['independent_check'])
        ledger,_=project_history.chain((root/'attempts.jsonl').read_text())
        self.assertEqual([x['phase'] for x in ledger],['BEGIN','START_FAILED','END']*2)
        self.history(root)
        self.assertFalse((root/'final-capture').exists())

    def test_invalid_request_has_no_session_or_output(self):
        args=arguments(ROOT/'invalid');args.request+=' Enable unrestricted network.'
        with self.assertRaises(ValueError):project.run_project(args)
        self.assertFalse(args.output.exists())

    def test_actual_controller_exit_leaves_detectable_unfinished_intent(self):
        root=ROOT/'controller-exit'
        code="""import os,pathlib,dataclasses,json
import development_project as p
from vm_session import Session
from test_project_session_controller import arguments
start=Session.start
def bounded(request,*a,**kw):
 s=start(dataclasses.replace(request,lifetime_seconds=1),*a,**kw)
 pathlib.Path(ROOT+'/observed-host-pid').write_text(str(s.child.pid))
 return s
def stop(*a,**kw):os._exit(71)
p.live_codex_planner.generate=stop
Session.start=bounded
p.run_project(arguments(pathlib.Path(ROOT)))
""".replace('ROOT',repr(str(root)))
        env=dict(os.environ,PYTHONPATH=str(SOURCE/'scripts/v7'),PYTHONDONTWRITEBYTECODE='1')
        r=subprocess.run([sys.executable,'-B','-c',code],cwd=SOURCE,env=env,capture_output=True,timeout=300)
        (ROOT/'controller-exit.stdout').write_bytes(r.stdout);(ROOT/'controller-exit.stderr').write_bytes(r.stderr)
        self.assertEqual(r.returncode,71,r.stderr)
        rows=(root/'attempts.jsonl').read_text();self.assertEqual(len(rows.splitlines()),2)
        freeze=worker.parse((root/'project-freeze.json').read_bytes())
        body=project_history.snapshot(root,worker.digest(worker.encoded(freeze)),[])
        with self.assertRaisesRegex(ValueError,'incomplete attempt closure'):
            project_history.audit(body,worker.digest(worker.encoded(body)))
        self.assertFalse((root/'final-capture').exists())


if __name__=='__main__':
    print('RETAINED_DEVELOPMENT_CONTROL_ROOT='+str(ROOT),flush=True)
    unittest.main()
