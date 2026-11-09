#!/usr/bin/env python3
"""Actual offline model/tool loop, confined to Linux development namespaces.

This is NOT a Firecracker producer, publisher, or host application authority.
The model chooses every coding action; no reference patch is embedded here.
Candidate code runs in the existing separate, read-only child sandbox.
"""
import argparse
import hashlib
import json
import os
import pathlib
import shutil
import signal
import subprocess
import sys
import time
import urllib.error
import urllib.request

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import coding_worker as worker
from fetch_offline_coder import MODELS, assets_for

MODEL_NAME = "coder-1.5b"
ASSETS = assets_for(MODEL_NAME)
CONTEXT = 'linux-development-namespace'

MAX_TURNS = 24
MAX_RESPONSE = 100000
SYSTEM = (
    "You are an autonomous coding agent repairing a three-file Python project. "
    "Choose exactly one tool action per response, as JSON matching the schema. "
    "The initial snapshot includes the existing files. Repair the implementation, improve its tests, and "
    "use check to obtain feedback. Write complete file contents using real newline "
    "characters, not literal backslash-n text. Finish only after check passes. "
    "You must change all three files. No shell, network or extra paths are available. "
    "The exact tool forms are {\"path\":\"totals.py\",\"text\":\"complete source code\",\"tool\":\"write\"}, "
    "{\"tool\":\"check\"}, and {\"tool\":\"finish\"}. Write paths are totals.py, "
    "report.py or test_totals.py. Use the keys tool, path and text exactly. "
    "The finish tool is available only after all three files change and the current files pass check. "
    "The workflow requires editing each initial file before verification. After a failed check, "
    "change code before checking again. The controller enforces these progress gates. "
    "Use compact standard-library code; each complete replacement must fit in 1024 characters. "
    "Prefer 6 to 15 short lines per file. Omit docstrings, commentary, headings, and repeated code. "
    "totals.py contains summarize(records), returning a category-to-integer dictionary. "
    "Validate the entire input: a list, exact category/amount keys, trimmed nonempty string category, "
    "and integer amount excluding bool. Raise ValueError for any invalid input; never skip bad records. "
    "report.py owns stdin/stdout: catch invalid JSON and validation errors and exit 2. "
    "test_totals.py must expect ValueError for invalid records, not an empty dictionary. "
    "test_totals.py contains the tests only. Do not append CLI or test blocks to totals.py. "
    "Do not repeat successful reads or checks indefinitely; make the needed edits."
)
SCHEMA = {"oneOf": [
    {"type": "object", "properties": {"tool": {"const": op}},
     "required": ["tool"], "additionalProperties": False}
    for op in ["check", "finish"]
] + [
    {"type": "object", "properties": {"tool": {"const": "write"},
     "path": {"enum": list(worker.FILES)}, "text": {"type": "string", "maxLength": 1024}},
     "required": ["tool", "path", "text"], "additionalProperties": False},
]}


def file_hash(path):
    h = hashlib.sha256()
    with path.open('rb') as f:
        while chunk := f.read(1024 * 1024):
            h.update(chunk)
    return h.hexdigest()


def contract():
    return {"schema": "realm.offline-coding-development.v1", "authority": "NONE",
            "model_name": MODEL_NAME,
            "execution_context": CONTEXT,
            "task": worker.contract(), "model_sha256": ASSETS[0]["sha256"],
            "runtime_archive_sha256": ASSETS[1]["sha256"], "max_turns": MAX_TURNS,
            "tokens_per_turn": 1024, "context_tokens": 4096, "replacement_character_limit": 1024,
            "context_rule": "current project snapshot plus latest feedback; full raw history retained separately",
            "completion_rule": "streamed action retained; require stop, refuse truncated/incomplete JSON before tools",
            "max_consecutive_unfinished_responses": 2,
            "max_consecutive_tool_refusals": 3,
            "request_timeout_seconds": 900 if MODEL_NAME == 'coder-7b' else 300,
            "run_timeout_seconds": 3600 if MODEL_NAME == 'coder-7b' else 1800,
            "protocol_schema": SCHEMA, "system_sha256": worker.digest(SYSTEM.encode()),
            "finish_rule": "all three files changed and independent check passes for the current exact tree",
            "progress_rule": "edit each initial file, then require check; failed check permits one changed repair before required recheck; passing current check permits finish only",
            "profile": ("read-only Firecracker development guest; private RAM run; no guest NIC; "
                        "separately sandboxed candidate checks; NOT_QUALIFIED"
                        if CONTEXT == 'firecracker-development-guest' else
                        "Linux unshare-all; read-only runtime/model; one private writable run; no host network or credentials; separately sandboxed candidate checks")}


def local_json(path, body=None, timeout=300):
    data = None if body is None else worker.encoded(body)
    req = urllib.request.Request('http://127.0.0.1:8080' + path, data=data,
                                 headers={"Content-Type": "application/json"})
    # Ignore all host proxy settings. Only the namespace-local inference service.
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    with opener.open(req, timeout=timeout) as response:
        raw = response.read(MAX_RESPONSE + 1)
    if len(raw) > MAX_RESPONSE:
        raise ValueError("local inference response limit")
    return worker.parse(raw)


def completion(body, base, turn):
    """Retain partial visible action text, but execute only a completed action."""
    req = urllib.request.Request('http://127.0.0.1:8080/v1/chat/completions',
        data=worker.encoded(body), headers={'Content-Type': 'application/json'})
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    deadline = time.monotonic() + contract()['request_timeout_seconds']
    content, reason, size = '', None, 0
    stream_path = base / f'model-stream-{turn:02}.jsonl'
    with opener.open(req, timeout=contract()['request_timeout_seconds']) as response, \
            stream_path.open('xb') as raw, (base / f'action-partial-{turn:02}.txt').open('xb') as partial:
        while line := response.readline(MAX_RESPONSE + 1):
            size += len(line)
            if len(line) > MAX_RESPONSE or size > 2 * 1024**2 or time.monotonic() > deadline:
                raise ValueError('bounded model stream exceeded')
            if not line.startswith(b'data: '):
                continue
            data = line[6:].strip()
            if data == b'[DONE]':
                break
            chunk = worker.parse(data)
            raw.write(worker.encoded(chunk) + b'\n')
            raw.flush()
            for choice in chunk.get('choices', []):
                addition = choice.get('delta', {}).get('content') or ''
                if type(addition) is not str:
                    raise ValueError('unsupported model action fragment')
                content += addition
                if len(content.encode()) > MAX_RESPONSE:
                    raise ValueError('model action size limit')
                partial.write(addition.encode())
                partial.flush()
                if choice.get('finish_reason'):
                    reason = choice['finish_reason']
        raw.flush()
        os.fsync(raw.fileno())
        partial.flush()
        os.fsync(partial.fileno())
    if reason != 'stop':
        raise ValueError('truncated/incomplete model response; no tool action executed')
    return {'choices': [{'message': {'content': content}, 'finish_reason': reason}],
            'stream_sha256': file_hash(stream_path)}


def feedback(result):
    if 'independent_cases' not in result:
        return worker.encoded(result).decode()
    cases = result['independent_cases']
    failures = [{k: row[k] for k in ('input', 'expected', 'exit', 'stdout', 'stderr')}
                for row in cases if not row['passed']][:4]
    return worker.encoded({"passed": result['passed'], "independent_passed": sum(r['passed'] for r in cases),
                           "independent_total": len(cases), "failures": failures,
                           "candidate_tests": result['candidate_tests']}).decode()


def action_schema(w, initial):
    current = w.tree()
    remaining = [p for p in worker.FILES if current[p] == initial[p]]
    alternatives = []
    for s in SCHEMA['oneOf']:
        tool = s['properties']['tool']['const']
        phase = 'initial' if remaining else (
            'finish' if w.last_check == (current, True) else
            'repair' if w.last_check == (current, False) else 'check')
        allowed = {'initial': {'write'}, 'repair': {'write'},
                   'check': {'check'}, 'finish': {'finish'}}
        if tool not in allowed[phase]:
            continue
        if tool == 'write' and remaining:
            s = json.loads(json.dumps(s))
            s['properties']['path']['enum'] = remaining
        alternatives.append(s)
    return {"oneOf": alternatives}


def guarded_request(w, initial, action):
    # Recheck at the actual tool boundary; model grammar is not a trusted guard.
    if type(action) is not dict:
        raise ValueError("object action required")
    matches = [row for row in action_schema(w, initial)['oneOf']
               if action.get('tool') == row['properties']['tool']['const']]
    if len(matches) != 1:
        raise ValueError("tool is outside the current write/check/repair/finish phase")
    schema = matches[0]
    if set(action) != set(schema['required']):
        raise ValueError("action fields differ from the current bounded schema")
    if action['tool'] == 'write':
        if action['path'] not in schema['properties']['path']['enum']:
            raise ValueError("write path is outside the current remaining-file scope")
        if type(action['text']) is not str or len(action['text']) > contract()['replacement_character_limit']:
            raise ValueError("complete replacement exceeds declared character limit")
        if worker.digest(action['text'].encode()) == w.tree()[action['path']]:
            raise ValueError("write does not change current file; use the independent check feedback to repair it")
    return w.request(action)


def inside():
    # Only the launcher supplies this fresh private mount; never a user workspace.
    base = pathlib.Path('/run/realm-task')
    model = pathlib.Path('/assets') / ASSETS[0]['name']
    runtime = pathlib.Path('/assets/runtime/llama-b11541')
    print('DEVELOPMENT_MODEL_HASH_START; AUTHORITY=NONE', flush=True)
    report = {"contract": contract(), "authority": "NONE", "realm_artifact": None,
              "controller_inside_guest": CONTEXT == 'firecracker-development-guest',
              "guest_execution_authenticated": False,
              "controller_inside_development_namespace": CONTEXT == 'linux-development-namespace',
              "status": "NOT_COMPLETE", "turns": [], "model_sha256": file_hash(model),
              "runtime_files": {p.name: file_hash(p) for p in runtime.iterdir() if p.is_file()}}
    print('DEVELOPMENT_MODEL_HASH_COMPLETE; AUTHORITY=NONE', flush=True)
    if report['model_sha256'] != ASSETS[0]['sha256']:
        raise ValueError('model changed after acquisition')
    server = None
    w = None
    def save():
        (base / 'agent-report.json').write_text(json.dumps(report, indent=2) + '\n')
    save()
    try:
        with (base / 'model-server.log').open('xb') as log:
            server = subprocess.Popen([str(runtime / 'llama-server'), '-m', str(model),
                                       '-c', str(contract()['context_tokens']), '-t', '2', '--parallel', '1',
                                       '--host', '127.0.0.1', '--port', '8080', '--no-webui',
                                       '--chat-template-kwargs', '{"enable_thinking":false}'],
                                      stdout=log, stderr=log, start_new_session=True,
                                      env={"PATH": "/usr/bin:/bin", "LC_ALL": "C", "LD_LIBRARY_PATH": str(runtime)},
                                      close_fds=True)
            print('DEVELOPMENT_MODEL_SERVER_START; AUTHORITY=NONE', flush=True)
            deadline = time.monotonic() + 120
            while True:
                if server.poll() is not None:
                    raise ValueError('offline model server exited before readiness')
                try:
                    local_json('/health', timeout=2)
                    break
                except (urllib.error.URLError, TimeoutError):
                    if time.monotonic() > deadline:
                        raise ValueError('offline model readiness timeout')
                    time.sleep(0.2)
            print('DEVELOPMENT_MODEL_SERVER_READY; AUTHORITY=NONE', flush=True)
            w = worker.Worker(base / 'run', worker.digest(worker.encoded(worker.contract())))
            initial = w.tree()
            print('DEVELOPMENT_BASELINE_CHECK_START; AUTHORITY=NONE', flush=True)
            baseline = w.request({"tool": "check"})
            report['baseline_passed'] = baseline['passed']
            save()
            latest = baseline
            last_check_feedback = baseline
            unfinished_responses = 0
            tool_refusals = 0
            for turn in range(MAX_TURNS):
                files = {name: worker.regular_read(w.fd, name).decode() for name in worker.FILES}
                progress = {"remaining_baseline_files": [p for p in worker.FILES if w.tree()[p] == initial[p]],
                            "available_tools": [s['properties']['tool']['const'] for s in action_schema(w, initial)['oneOf']]}
                messages = [{"role": "system", "content": SYSTEM},
                            {"role": "user", "content": worker.DESCRIPTION + '\nCurrent files: '
                             + worker.encoded(files).decode() + '\nLatest tool feedback: ' + feedback(latest)
                             + '\nMost recent independent check: ' + feedback(last_check_feedback)
                             + '\nWorkflow state: ' + worker.encoded(progress).decode()}]
                if len(worker.encoded(messages)) > 30000:
                    raise ValueError('bounded model context exhausted')
                schema = action_schema(w, initial)
                body = {"messages": messages, "temperature": 0, "seed": 123,
                        "max_tokens": contract()['tokens_per_turn'], "stream": True,
                        "response_format": {"type": "json_schema", "json_schema":
                                            {"name": "coding_action", "strict": True, "schema": schema}}}
                (base / f'prompt-{turn:02}.json').write_bytes(worker.encoded(body))
                print(json.dumps({'turn': turn, 'status': 'MODEL_REQUEST_START', 'authority': 'NONE'}), flush=True)
                started = time.monotonic()
                try:
                    response = completion(body, base, turn)
                except (ValueError, TimeoutError, urllib.error.URLError) as exc:
                    latest = {'status': 'REFUSED', 'authority': 'NONE',
                              'error': str(exc) + '; return a smaller complete action'}
                    w.last_check = None
                    w.event({'refusal': latest, 'request_sha256': file_hash(base / f'prompt-{turn:02}.json')})
                    report['turns'].append({'turn': turn, 'action': {'tool': 'NO_ACTION'},
                                           'result': latest, 'seconds': time.monotonic() - started})
                    save()
                    print(json.dumps({'turn': turn, 'tool': 'NO_ACTION', 'status': 'REFUSED',
                                      'error': str(exc), 'authority': 'NONE'}), flush=True)
                    unfinished_responses += 1
                    if unfinished_responses >= contract()['max_consecutive_unfinished_responses']:
                        raise ValueError('consecutive unfinished responses; export diagnostics before retrying another input')
                    continue
                unfinished_responses = 0
                (base / f'response-{turn:02}.json').write_bytes(worker.encoded(response))
                text = response['choices'][0]['message']['content']
                action = worker.parse(text)
                if action.get('tool') == 'finish' and any(w.tree()[p] == initial[p] for p in worker.FILES):
                    result = {"status": "REFUSED", "error": "all three files must change", "authority": "NONE"}
                    w.event({"refusal": result, "request_sha256": worker.digest(worker.encoded(action))})
                else:
                    try:
                        result = guarded_request(w, initial, action)
                    except (ValueError, OSError, TypeError) as exc:
                        result = {"status": "REFUSED", "error": str(exc), "authority": "NONE"}
                        w.event({"refusal": result, "request_sha256": worker.digest(worker.encoded(action))})
                row = {"turn": turn, "action": action, "result": result,
                       "seconds": time.monotonic() - started, "response_sha256": file_hash(base / f'response-{turn:02}.json')}
                report['turns'].append(row)
                save()
                print(json.dumps({"turn": turn, "tool": action.get('tool'), "path": action.get('path'),
                                  "passed": result.get('passed'), "status": result.get('status')}), flush=True)
                tool_refusals = tool_refusals + 1 if result.get('status') == 'REFUSED' else 0
                if tool_refusals >= contract()['max_consecutive_tool_refusals']:
                    raise ValueError('consecutive refused tools; export diagnostics before another fresh input')
                if w.done:
                    report['status'] = 'DEVELOPMENT_TASK_CHECKED'
                    report['files'] = w.tree()
                    break
                if 'independent_cases' in result:
                    last_check_feedback = result
                latest = result
            else:
                raise ValueError('autonomous turn limit reached')
    except Exception as exc:
        report['failure'] = type(exc).__name__ + ': ' + str(exc)
        raise
    finally:
        if w:
            w.close()
        if server:
            try:
                os.killpg(server.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            server.wait()
            report['model_server_exit'] = server.returncode
        save()


def main():
    global ASSETS, MODEL_NAME, CONTEXT
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('command', choices=['draft', 'launch', 'inside'])
    ap.add_argument('--root', type=pathlib.Path)
    ap.add_argument('--assets', type=pathlib.Path)
    ap.add_argument('--approve')
    ap.add_argument('--model', choices=sorted(MODELS), default='coder-1.5b')
    ap.add_argument('--context', choices=['linux-development-namespace', 'firecracker-development-guest'],
                    default='linux-development-namespace')
    args = ap.parse_args()
    MODEL_NAME = args.model
    ASSETS = assets_for(MODEL_NAME)
    CONTEXT = args.context
    approval = worker.digest(worker.encoded(contract()))
    if args.command == 'draft':
        print(json.dumps({"contract": contract(), "approval": approval}, indent=2))
        return
    if args.command == 'inside':
        inside()
        return
    if CONTEXT != 'linux-development-namespace':
        ap.error('host launcher only supports development namespaces; guest entry requires a separate probe')
    if args.approve != approval:
        ap.error('exact offline development contract approval required')
    if sys.platform != 'linux' or not shutil.which('bwrap'):
        ap.error('Linux bubblewrap required; no fallback')
    if not args.root or not args.root.is_absolute() or args.root.exists() or not args.assets:
        ap.error('fresh absolute task-owned root and acquired assets required')
    assets = args.assets.resolve(strict=True)
    if json.loads((assets / 'assets.json').read_text())['assets'] != list(ASSETS):
        ap.error('asset acquisition manifest differs')
    if file_hash(assets / ASSETS[1]['name']) != ASSETS[1]['sha256']:
        ap.error('runtime archive changed')
    args.root.mkdir(mode=0o700)
    scripts = pathlib.Path(__file__).resolve().parent
    command = ['bwrap', '--unshare-all', '--die-with-parent', '--new-session',
               '--cap-drop', 'ALL', '--clearenv', '--ro-bind', '/usr', '/usr']
    for name in ('/bin', '/lib', '/lib64'):
        p = pathlib.Path(name)
        if p.is_symlink():
            command += ['--symlink', os.readlink(p), name]
        elif p.exists():
            command += ['--ro-bind', name, name]
    command += ['--proc', '/proc', '--dev', '/dev', '--tmpfs', '/tmp',
                '--ro-bind', str(assets), '/assets', '--ro-bind', str(scripts), '/controller',
                '--bind', str(args.root), '/run/realm-task', '--chdir', '/run/realm-task',
                '/usr/bin/python3', '-I', '-B', '/controller/offline_coding_agent.py', 'inside', '--model', MODEL_NAME]
    (args.root / 'launch.json').write_bytes(worker.encoded({"contract": contract(), "approval": approval,
        "command": command, "authority": "NONE", "source_files":
        {name: file_hash(scripts / name) for name in ('offline_coding_agent.py', 'coding_worker.py', 'fetch_offline_coder.py')}}))
    child = subprocess.Popen(command, start_new_session=True, close_fds=True,
                             env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"})
    try:
        code = child.wait(timeout=contract()['run_timeout_seconds'])
    finally:
        try:
            os.killpg(child.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        child.wait()
    raise SystemExit(code)


if __name__ == '__main__':
    main()
