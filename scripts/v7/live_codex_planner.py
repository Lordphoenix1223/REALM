"""Thin supported Codex CLI adapter for the existing development tool loop.

No candidate execution, oracle, artifact encoder, receiver or authority here.
Only public requirements/baseline/current files and observed feedback are sent.
"""
import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import time


def schema(files):
    # Required source fields avoid degenerate anyOf action-array decoding.
    return {'type': 'object', 'properties': {'files': {
        'type': 'object', 'properties': {n: {'type': 'string'} for n in files},
        'required': list(files), 'additionalProperties': False}},
        'required': ['files'], 'additionalProperties': False}


def generate(worker, run, responses, generation, timeout, *, candidate_root=None):
    if generation > 2:
        raise ValueError('two fresh planner generations exhausted')
    codex = shutil.which('codex')
    if codex is None:
        raise ValueError('supported codex CLI is unavailable; no saved-solution fallback')
    # Do not inherit desktop/session pipes, policy, memory or API routing.
    # CODEX_HOME, if explicitly selected, is only the existing auth store.
    env = {k: v for k, v in os.environ.items()
           if (not k.startswith(('CODEX_', 'OPENAI_')) or k == 'CODEX_HOME')}
    auth = subprocess.run([codex, 'login', 'status'], capture_output=True, env=env, timeout=10)
    if auth.returncode or b'Logged in using ChatGPT' not in auth.stdout + auth.stderr:
        raise ValueError('existing ChatGPT login required; no login or paid API fallback')
    directory = run / ('planner-%02d' % generation); directory.mkdir(mode=0o700)
    empty = directory / 'empty'; empty.mkdir(mode=0o700)
    def save(name, raw):
        with (directory / name).open('xb') as f:
            os.fchmod(f.fileno(), 0o600); f.write(raw); f.flush(); os.fsync(f.fileno())
    # Deliberately no repository path, oracle, hidden cases, prior solve or chat.
    feedback = [r['response'] for r in responses
                if r['action'] != {'tool': 'read', 'path': '../outside.py'}]
    candidate = Path(candidate_root) if candidate_root is not None else run / 'worker/candidate'
    context = {'requirements': worker.DESCRIPTION, 'files': list(worker.FILES),
               'runtime_contract': {'candidate_filesystem': 'read-only', 'network': False,
                                    'process_fork': False, 'wall_seconds_per_process': 3,
                                    'stdout_and_stderr_each_max_bytes': worker.MAX_BYTES,
                                    'baseline_mutation_test_output_also_bounded': True},
               'baseline': worker.BASELINE,
               'read_only_dependencies': getattr(worker, 'READ_ONLY_DEPENDENCIES', {}),
               'current_files': {n: (candidate / n).read_text() for n in worker.FILES},
               'feedback': feedback[-1] if feedback else None,
               'unchanged_files_requiring_writes': [n for n in worker.FILES
                   if (candidate / n).read_text() == worker.BASELINE[n]]}
    prompt = ('Solve this new three-file coding task using only the given input. Return JSON with '
              'a files object containing complete Python source strings for exactly the permitted files '
              'listed in the input. Preserve every read_only_dependency byte. Generate working '
              'implementation and meaningful tests, not instructions. '
              'The controller will write these exact bytes through restricted REALM tools, run independent '
              'checks, and finish only after a passing exact-tree check. A failed check permits one '
              'repair generation. Use only the standard library; no shell, web, outside files or tools. '
              'summarize(value) must raise ValueError for invalid inputs. Tests must reject the baseline. '
              'Honor runtime_contract: tests cannot spawn subprocesses; test main/runpy in process if needed. '
              'Use a small discriminating test suite whose failing-baseline output also fits the output cap.\n'
              + worker.encoded(context).decode())
    save('prompt.txt', prompt.encode()); save('schema.json', worker.encoded(schema(worker.FILES)))
    command = [codex, 'exec', '--ignore-user-config', '--ephemeral', '--sandbox', 'read-only',
               '--disable', 'shell_tool', '--disable', 'multi_agent', '--disable', 'apps',
               '--disable', 'plugins', '--disable', 'memories', '-c', 'web_search="disabled"',
               '-c', 'model_reasoning_effort="low"',
               '--skip-git-repo-check', '--cd', str(empty), '--json',
               '--output-schema', str(directory / 'schema.json'),
               '--output-last-message', str(directory / 'answer.json'), '-']
    save('command.json', worker.encoded(command))
    start = time.monotonic(); timed_out = False
    with (directory / 'events.jsonl').open('xb') as so, (directory / 'stderr').open('xb') as se:
        child = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=so, stderr=se,
                                 env=env, start_new_session=True)
        try:
            child.communicate(prompt.encode(), timeout=timeout)
        except subprocess.TimeoutExpired:
            timed_out = True
        finally:
            try:
                os.killpg(child.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            child.wait()
    events = []
    for line in (directory / 'events.jsonl').read_bytes().splitlines():
        try:
            events.append(json.loads(line))
        except ValueError:
            pass
    usage = [e.get('usage') for e in events if e.get('type') == 'turn.completed']
    items = [e.get('item', {}).get('type') for e in events if e.get('type', '').startswith('item.')]
    record = {'argv': command, 'exit': child.returncode, 'timed_out': timed_out,
              'elapsed_seconds': time.monotonic() - start, 'usage': usage, 'item_types': items,
              'auth': 'EXISTING_CHATGPT_PLAN', 'monetary_cost': 'NOT_REPORTED', 'authority': 'NONE'}
    save('RESULT.json', worker.encoded(record))
    if timed_out or child.returncode:
        raise ValueError('fresh Codex planner failed; inspect retained planner RESULT/stderr')
    if any(t not in ('reasoning', 'agent_message') for t in items):
        raise ValueError('unexpected planner tool activity; no actions dispatched')
    answer = worker.parse((directory / 'answer.json').read_bytes())
    if (type(answer) is not dict or set(answer) != {'files'} or
            type(answer['files']) is not dict or set(answer['files']) != set(worker.FILES) or
            any(type(text) is not str or not 0 < len(text.encode()) <= worker.MAX_BYTES
                for text in answer['files'].values())):
        raise ValueError('bounded complete planner source files required')
    # Only scheduling is fixed here. Every source byte comes from this fresh
    # model response; no candidate PASS/finish result is synthesized.
    return ([{'tool': 'write', 'path': n, 'text': answer['files'][n]} for n in worker.FILES]
            + [{'tool': 'check'}, {'tool': 'finish'}])
