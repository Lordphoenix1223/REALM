#!/usr/bin/env python3
"""Bounded coding-tool development worker. NEVER a V6 authority producer.

The controller is external; candidate execution uses Seatbelt or bubblewrap.
No model API, arbitrary shell, publication, destination application or .realm.
Private run directory and exclusive ownership are required. Not crash recovery.
"""
import argparse
import hashlib
import json
import os
import pathlib
import platform
import random
import resource
import selectors
import shutil
import signal
import stat
import subprocess
import sys
import time

FILES = ("totals.py", "report.py", "test_totals.py")
MAX_BYTES = 32768
MAX_REQUESTS = 128
DESCRIPTION = (
    "Repair totals.py and report.py and update test_totals.py. Read a JSON list "
    "of transactions from stdin, trim each nonempty string category, and sum "
    "integer amounts (including negative refunds) by category. Each object must have exactly category and amount. Booleans are "
    "invalid amounts. Print {totals:[{category,amount}],net:integer} with categories "
    "sorted lexicographically. Invalid input must exit 2. Use only the Python "
    "standard library. Only these three flat files may change."
)
BASELINE = {
    "totals.py": "def summarize(records):\n    totals = {}\n    for r in records:\n        if r['amount'] > 0:\n            totals[r['category']] = totals.get(r['category'], 0) + r['amount']\n    return totals\n",
    "report.py": "import json, sys\nfrom totals import summarize\nt = summarize(json.load(sys.stdin))\nprint(json.dumps({'totals': [{'category': k, 'amount': v} for k, v in t.items()], 'net': sum(t.values())}))\n",
    "test_totals.py": "import unittest\nfrom totals import summarize\nclass Tests(unittest.TestCase):\n    def test_positive(self):\n        self.assertEqual(summarize([{'category':'A','amount':3}]), {'A':3})\nif __name__ == '__main__':\n    unittest.main()\n",
}


def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


def digest(data):
    return hashlib.sha256(data).hexdigest()


def pairs(items):
    out = {}
    for key, value in items:
        if key in out:
            raise ValueError("duplicate JSON key")
        out[key] = value
    return out


def parse(data):
    return json.loads(data, object_pairs_hook=pairs,
                      parse_constant=lambda _: (_ for _ in ()).throw(ValueError("nonfinite JSON")))


def contract():
    result = {"schema": "realm.coding-development.v1", "description": DESCRIPTION,
            "files": list(FILES), "baseline": {k: digest(v.encode()) for k, v in BASELINE.items()},
            "max_file_bytes": MAX_BYTES, "max_requests": MAX_REQUESTS,
            "tools": ["list", "read", "write", "check", "finish"],
            "authority": "NONE", "runtime": "kernel-child-development-only"}
    if DEVELOPMENT_TASK is not None:
        result["development_task"] = dict(DEVELOPMENT_TASK)
    return result


# Explicit development CLI configuration only. Native imports retain the fixed
# original task; no environment variable or candidate-selected module is loaded.
DEVELOPMENT_TASK = None


def configure_development_task(path, pin):
    global DEVELOPMENT_TASK, DESCRIPTION, BASELINE
    raw = path.read_bytes()
    if digest(raw) != pin:
        raise ValueError("development task definition pin differs")
    task = parse(raw)
    if type(task) is dict and task.get('schema') == 'realm.fresh-functional-task.v1':
        if (set(task) != {'schema', 'id', 'description', 'baseline', 'kind', 'acceptance_inputs'} or
                task['kind'] not in ('interval-union', 'dependency-order', 'unicode-runs') or
                type(task['id']) is not str or not task['id'] or
                type(task['description']) is not str or not task['description'] or
                type(task['baseline']) is not dict or set(task['baseline']) != set(FILES) or
                any(type(v) is not str or not 0 < len(v.encode()) <= MAX_BYTES
                    for v in task['baseline'].values()) or
                type(task['acceptance_inputs']) is not list or
                not 1 <= len(task['acceptance_inputs']) <= 32):
            raise ValueError('unsupported functional task definition')
        DEVELOPMENT_TASK = {k: task[k] for k in ('id', 'kind', 'acceptance_inputs')}
        DEVELOPMENT_TASK['definition_sha256'] = pin
        DESCRIPTION, BASELINE = task['description'], task['baseline']
        return
    if (type(task) is not dict or set(task) !=
            {"schema", "id", "description", "baseline", "normalization", "omit_zero"}
            or task["schema"] != "realm.fresh-development-task.v1"
            or type(task["id"]) is not str or not task["id"]
            or type(task["description"]) is not str or not task["description"]
            or type(task["baseline"]) is not dict or set(task["baseline"]) != set(FILES)
            or any(type(v) is not str or not 0 < len(v.encode()) <= MAX_BYTES
                   for v in task["baseline"].values())
            or task["normalization"] not in ("casefold", "nfc")
            or type(task["omit_zero"]) is not bool):
        raise ValueError("unsupported fresh development task definition")
    DEVELOPMENT_TASK = {"id": task["id"], "normalization": task["normalization"],
                        "omit_zero": task["omit_zero"], "definition_sha256": pin}
    DESCRIPTION, BASELINE = task["description"], task["baseline"]


def regular_read(fd, name):
    f = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fd)
    try:
        info = os.fstat(f)
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_uid != os.getuid():
            raise ValueError("file identity refused")
        if info.st_size > MAX_BYTES:
            raise ValueError("file size refused")
        data = os.read(f, MAX_BYTES + 1)
        if len(data) != info.st_size:
            raise ValueError("file changed or oversized")
        return data
    finally:
        os.close(f)


class Sandbox:
    def __init__(self, candidate, *, evidence_channel_guard=False):
        self.candidate = candidate.resolve(strict=True)
        self.python = pathlib.Path(sys.executable).resolve(strict=True)
        self.backend = platform.system()
        if type(evidence_channel_guard) is not bool:
            raise ValueError("REFUSE: candidate channel policy must be explicit bool")
        self.evidence_channel_guard = evidence_channel_guard
        if evidence_channel_guard:
            import candidate_channel_guard
            candidate_channel_guard.require_platform()
        app_python = pathlib.Path(sys.base_prefix).resolve() / "Resources/Python.app/Contents/MacOS/Python"
        if self.backend == "Darwin" and app_python.is_file():
            self.python = app_python.resolve()
        if self.backend == "Darwin":
            if not pathlib.Path("/usr/bin/sandbox-exec").is_file():
                raise ValueError("REFUSE: Seatbelt launcher unavailable")
            # Runtime/library reads only; no HOME, credential, journal or oracle mount.
            roots = [self.candidate, pathlib.Path(sys.prefix).resolve(),
                     pathlib.Path("/System"), pathlib.Path("/usr/lib"),
                     pathlib.Path("/private/var/db/dyld"), pathlib.Path("/Library/Apple/System/Library"),
                     pathlib.Path("/opt/homebrew/Cellar")]  # Homebrew dylib dependencies.
            ancestors = set(self.candidate.parents) | set(self.python.parents)
            literals = " ".join("(literal " + json.dumps(str(p)) + ")" for p in ancestors)
            rules = " ".join('(subpath ' + json.dumps(str(p)) + ')' for p in roots)
            self.profile = ('(version 1)(deny default)(allow process-exec (literal '
                            + json.dumps(str(self.python)) + '))(allow file-read* '
                            + rules + ' (literal "/dev/null") (literal "/dev/urandom"))'
                            + "(allow file-read* " + literals + ")"
                            + '(allow sysctl-read)(deny network*)(deny process-fork)')
            self.prefix = ["/usr/bin/sandbox-exec", "-p", self.profile, str(self.python), "-I", "-B"]
        elif self.backend == "Linux":
            bwrap = shutil.which("bwrap")
            if not bwrap or not str(self.python).startswith("/usr/"):
                raise ValueError("REFUSE: bubblewrap and /usr Python required")
            self.prefix = [bwrap, "--unshare-all", "--die-with-parent", "--new-session",
                           "--cap-drop", "ALL", "--clearenv", "--ro-bind", "/usr", "/usr"]
            for name in ("/bin", "/lib", "/lib64"):
                if pathlib.Path(name).is_symlink():
                    self.prefix += ["--symlink", os.readlink(name), name]
                elif pathlib.Path(name).exists():
                    self.prefix += ["--ro-bind", name, name]
            self.prefix += ["--proc", "/proc", "--dev", "/dev", "--tmpfs", "/tmp",
                            "--ro-bind", str(self.candidate), "/work", "--chdir", "/work",
                            str(self.python), "-I", "-B"]
            self.profile = "bubblewrap:unshare-all,ro-usr,ro-work,private-tmp,no-capabilities"
            if evidence_channel_guard:
                self.profile += "," + candidate_channel_guard.POLICY
        else:
            raise ValueError("REFUSE: no supported kernel child sandbox")

    def run(self, script, data):
        # Fixed wrapper; tool callers never choose a program or command arguments.
        cwd = str(self.candidate) if self.backend == "Darwin" else "/work"
        wrapper = "import sys,runpy;sys.path.insert(0," + repr(cwd) + ");runpy.run_path(" + repr(cwd + "/" + script) + ",run_name='__main__')"
        return self.execute(wrapper, data)

    def execute(self, wrapper, data):
        command = self.prefix + ["-c", wrapper]
        deadline = time.monotonic() + 3
        def limits():
            resource.setrlimit(resource.RLIMIT_CPU, (2, 2))
            resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
            if self.backend == "Linux":
                resource.setrlimit(resource.RLIMIT_AS, (256 * 1024 * 1024,) * 2)
                if self.evidence_channel_guard:
                    import candidate_channel_guard
                    candidate_channel_guard.install()
        child = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                 stderr=subprocess.PIPE, env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"},
                                 cwd=self.candidate, start_new_session=True, close_fds=True, preexec_fn=limits)
        streams = {"stdout": bytearray(), "stderr": bytearray()}
        selector = selectors.DefaultSelector()
        try:
            for name in streams:
                os.set_blocking(getattr(child, name).fileno(), False)
                selector.register(getattr(child, name), selectors.EVENT_READ, name)
            offset = 0
            if data:
                os.set_blocking(child.stdin.fileno(), False)
                selector.register(child.stdin, selectors.EVENT_WRITE, 'stdin')
            else:
                child.stdin.close()
            while selector.get_map():
                if time.monotonic() > deadline:
                    raise ValueError("candidate timeout")
                for key, _ in selector.select(timeout=min(0.1, max(0, deadline-time.monotonic()))):
                    if key.data == 'stdin':
                        try:
                            offset += os.write(key.fileobj.fileno(), data[offset:offset+4096])
                        except BlockingIOError:
                            continue
                        except BrokenPipeError as error:
                            raise ValueError('candidate closed input before full delivery') from error
                        if offset == len(data):
                            selector.unregister(child.stdin)
                            child.stdin.close()
                        continue
                    try:
                        chunk = os.read(key.fileobj.fileno(), 4096)
                    except BlockingIOError:
                        continue
                    if not chunk:
                        selector.unregister(key.fileobj)
                    else:
                        streams[key.data].extend(chunk)
                        if len(streams[key.data]) > MAX_BYTES:
                            raise ValueError("candidate output limit")
            code = child.wait(timeout=max(0.01, deadline - time.monotonic()))
            return code, bytes(streams["stdout"]), bytes(streams["stderr"])
        finally:
            try:
                if getattr(self, 'linux_stage8_pid1', False):
                    # The no-fork Stage8 profile runs as namespace PID 1. Kill
                    # that child first, leaving bwrap alive to wait/reap it.
                    # Killing the group first orphans its zombie externally.
                    if child.poll() is None:
                        try:
                            pids = pathlib.Path(f'/proc/{child.pid}/task/{child.pid}/children').read_text().split()
                            if len(pids) != 1:
                                raise ValueError('REFUSE: Linux launcher child ownership incomplete')
                            pid = int(pids[0])
                            fd = os.pidfd_open(pid)
                            try:
                                status = pathlib.Path(f'/proc/{pid}/status').read_text().splitlines()
                                if f'PPid:\t{child.pid}' not in status:
                                    raise ValueError('REFUSE: Linux launcher child parent changed')
                                signal.pidfd_send_signal(fd, signal.SIGKILL)
                            finally:
                                os.close(fd)
                            child.wait(timeout=1)
                        except (ProcessLookupError, FileNotFoundError):
                            child.wait(timeout=1)
                        except BaseException:
                            # Best-effort containment on an ownership failure;
                            # never return success or claim clean closure.
                            try:
                                os.killpg(child.pid, signal.SIGKILL)
                            except ProcessLookupError:
                                pass
                            child.wait()
                            raise
                else:
                    # Shared development transport: same-group cleanup only.
                    try:
                        os.killpg(child.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                    child.wait()
            finally:
                selector.close()
                for stream in (child.stdin, child.stdout, child.stderr):
                    if not stream.closed:
                        stream.close()


def conformance(sandbox, sentinel):
    candidate = str(sandbox.candidate) if sandbox.backend == "Darwin" else "/work"
    code = """import os,socket,json
results={}
def deny(name,action):
    try:
        action()
    except OSError:
        results[name]=True
    else:
        results[name]=False
with open(CANDIDATE+'/totals.py') as f: results['candidate_read']=bool(f.read())
deny('candidate_write',lambda:open(CANDIDATE+'/totals.py','wb'))
deny('protected_read',lambda:open(SENTINEL,'rb'))
deny('protected_write',lambda:open(SENTINEL,'wb'))
deny('network',lambda:socket.socket().connect(('127.0.0.1',9)))
print(json.dumps(results))
""".replace("CANDIDATE", repr(candidate)).replace("SENTINEL", repr(str(sentinel)))
    before = sentinel.read_bytes()
    code_status, out, err = sandbox.execute(code, b"")
    result = parse(out) if code_status == 0 else {}
    if result != dict.fromkeys(["candidate_read", "candidate_write", "protected_read", "protected_write", "network"], True) or sentinel.read_bytes() != before:
        raise ValueError("REFUSE: development sandbox conformance failed: " + err.decode(errors="replace"))
    return result


def expected(records):
    if DEVELOPMENT_TASK is not None and "kind" in DEVELOPMENT_TASK:
        from development_task_oracles import expected as task_expected
        return task_expected(DEVELOPMENT_TASK["kind"], records)
    if not isinstance(records, list):
        return None
    totals = {}
    for row in records:
        if not isinstance(row, dict) or set(row) != {"category", "amount"}:
            return None
        category, amount = row["category"], row["amount"]
        if not isinstance(category, str) or not category.strip() or type(amount) is not int:
            return None
        key = category.strip()
        if DEVELOPMENT_TASK is not None:
            if DEVELOPMENT_TASK['normalization'] == 'casefold':
                key = key.casefold()
            else:
                import unicodedata
                key = unicodedata.normalize('NFC', key)
        totals[key] = totals.get(key, 0) + amount
    if DEVELOPMENT_TASK is not None and DEVELOPMENT_TASK["omit_zero"]:
        totals = {k: v for k, v in totals.items() if v != 0}
    return {"totals": [{"category": k, "amount": totals[k]} for k in sorted(totals)],
            "net": sum(totals.values())}


def check_cases(seed):
    rng = random.Random(seed)
    cases = [[], [{"category": " B ", "amount": 4}, {"category": "A", "amount": -7},
                  {"category": "B", "amount": -9}], {}, [None],
             [{"category": "A", "amount": True}], [{"category": " ", "amount": 1}],
             [{"category": "A", "amount": "1"}], [{"category": 3, "amount": 1}],
             [{"category": "A", "amount": 1, "extra": 1}]]
    if DEVELOPMENT_TASK is not None and "normalization" in DEVELOPMENT_TASK:
        cases += [[{"category": " Straße ", "amount": 8}, {"category": "STRASSE", "amount": -8}],
                  [{"category": "e\u0301", "amount": 2}, {"category": "é", "amount": 3},
                   {"category": " zero ", "amount": 0}]]
    for _ in range(8):
        cases.append([{"category": rng.choice(["A", "z", " B ", "é"]),
                       "amount": rng.randint(-10000, 10000)} for _ in range(rng.randint(1, 16))])
    if DEVELOPMENT_TASK is not None and "kind" in DEVELOPMENT_TASK:
        cases = DEVELOPMENT_TASK["acceptance_inputs"]
    return cases


def check(sandbox, seed):
    rows = []
    for n, inputs in enumerate(check_cases(seed)):
        code, out, err = sandbox.run("report.py", encoded(inputs))
        oracle = expected(inputs)
        try:
            passed = code == 2 if oracle is None else code == 0 and encoded(parse(out)) == encoded(oracle)
        except ValueError:
            passed = False
        rows.append({"case": n, "input": inputs, "expected": oracle, "passed": passed,
                     "exit": code, "stdout": out.decode(errors="replace"),
                     "stderr": err.decode(errors="replace")})
    code, out, err = sandbox.run("test_totals.py", b"")
    return {"independent_cases": rows, "passed": all(row["passed"] for row in rows) and code == 0,
            "candidate_tests": {"exit": code, "stdout": out.decode(errors="replace"),
                                "stderr": err.decode(errors="replace"), "trusted_oracle": False}}


class Worker:
    def __init__(self, root, approval, *, evidence_channel_guard=False, native_subtask=None):
        if approval != digest(encoded(contract())):
            raise ValueError("REFUSE: exact development contract approval required")
        if type(evidence_channel_guard) is not bool:
            raise ValueError("REFUSE: candidate channel policy must be explicit bool")
        if evidence_channel_guard:
            import candidate_channel_guard
            candidate_channel_guard.require_platform()
        root.mkdir(mode=0o700)  # Fresh task-owned directory; never a user workspace.
        self.evidence_channel_guard = evidence_channel_guard
        self.root = root.resolve(strict=True)
        self.candidate = self.root / "candidate"
        self.candidate.mkdir(mode=0o700)
        self.fd = os.open(self.candidate, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        self.journal = open(self.root / "events.jsonl", "xb", buffering=0)
        os.chmod(self.root / "events.jsonl", 0o600)
        self.head = "0" * 64
        self.count = 0
        self.done = False
        self.last_check = None
        self.native_subtask = native_subtask
        if native_subtask is not None:
            if (not evidence_channel_guard or DEVELOPMENT_TASK is not None
                or native_subtask.get('role') not in ('api','cli')):
                raise ValueError('registered original native subtask required')
        for name, content in BASELINE.items():
            self.write(name, content.encode())
        if native_subtask is not None and native_subtask['role']=='cli':
            import coding_native_client
            predecessor=native_subtask.get('predecessor')
            if type(predecessor) is not dict: raise ValueError('native CLI predecessor required')
            packet=coding_native_client.packet(bytes.fromhex(predecessor['packet_hex']),predecessor['submission'])
            for file in packet['files']: self.write(file['path'],file['text'].encode())
        sentinel = self.root / "protected-sentinel"
        sentinel.write_bytes(os.urandom(32))
        sentinel.chmod(0o600)
        self.event({"contract": contract(), "contract_sha256": approval,
                    "worker_sha256": digest(pathlib.Path(__file__).read_bytes()),
                    "platform": platform.platform(), "authority": "NONE"})

    def event(self, row):
        body = {"sequence": self.count, "previous": self.head, "event": row}
        self.head = digest(encoded(body))
        data = memoryview(encoded({**body, "sha256": self.head}) + b"\n")
        while data:
            written = self.journal.write(data)
            if not written:
                raise OSError("short journal write")
            data = data[written:]
        os.fsync(self.journal.fileno())
        self.count += 1

    def tree(self):
        if set(os.listdir(self.fd)) != set(FILES):
            raise ValueError("REFUSE: candidate file set differs")
        return {name: digest(regular_read(self.fd, name)) for name in FILES}

    def write(self, name, data):
        if name not in FILES or len(data) > MAX_BYTES:
            raise ValueError("REFUSE: unsupported path or size")
        temp = ".stage"
        f = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=self.fd)
        try:
            with os.fdopen(f, "wb") as output:
                output.write(data)
                output.flush()
                os.fsync(output.fileno())
            os.rename(temp, name, src_dir_fd=self.fd, dst_dir_fd=self.fd)
            os.fsync(self.fd)
        finally:
            try:
                os.unlink(temp, dir_fd=self.fd)
            except FileNotFoundError:
                pass

    def request(self, request):
        if self.done or self.count >= MAX_REQUESTS:
            raise ValueError("REFUSE: task closed or request limit")
        before = self.tree()
        if not isinstance(request, dict):
            raise ValueError("REFUSE: object request required")
        op = request.get("tool")
        schema = {"list": {"tool"}, "read": {"tool", "path"},
                  "write": {"tool", "path", "text"}, "check": {"tool"}, "finish": {"tool"}}
        if op not in schema or set(request) != schema[op]:
            raise ValueError("REFUSE: unsupported tool or fields")
        if op in ("read", "write") and request["path"] not in FILES:
            raise ValueError("REFUSE: path outside scope")
        if op == "list":
            result = {"files": before, "task": DESCRIPTION}
        elif op == "read":
            result = {"text": regular_read(self.fd, request["path"]).decode()}
        elif op == "write":
            if self.native_subtask is not None:
                allowed=('totals.py','test_totals.py') if self.native_subtask['role']=='api' else ('report.py','test_totals.py')
                if request['path'] not in allowed: raise ValueError('write violates registered native subtask')
            if not isinstance(request["text"], str):
                raise ValueError("REFUSE: text required")
            self.write(request["path"], request["text"].encode())
            self.last_check = None
            result = {"written": request["path"]}
        elif op == "check":
            self.last_check = None
            sandbox = Sandbox(self.candidate, evidence_channel_guard=self.evidence_channel_guard)
            seed = int.from_bytes(os.urandom(16), "big")
            checks = conformance(sandbox, self.root / "protected-sentinel")
            if self.native_subtask is not None and self.native_subtask['role']=='api':
                import coding_task_verifier as native_referee
                result=native_referee.verify_native_api(self.candidate,self.root/('native-api-check-'+str(self.count)),
                    digest(encoded(native_referee.native_api_scope())),seed)
                result['passed']=result['status']=='PASS_API_SUBTASK'
            else:
                result = check(sandbox, seed)
            result["development_conformance"] = checks
            result.update(seed=seed, sandbox=sandbox.profile,
                          interpreter_sha256=digest(sandbox.python.read_bytes()))
            self.last_check = (before, result["passed"])
        else:
            if self.last_check != (before, True):
                raise ValueError("REFUSE: independent check required for exact current tree")
            result = {"status": "DEVELOPMENT_TASK_CHECKED", "files": before,
                      "authority": "NONE", "realm_artifact": None,
                      "history_complete": False, "controller_inside_guest": False}
            self.done = True
        after = self.tree()
        if op != "write" and before != after:
            raise ValueError("REFUSE: unexpected candidate mutation")
        self.event({"request": request, "result": result, "before": before, "after": after})
        return result

    def close(self):
        self.journal.close()
        os.close(self.fd)


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("command", choices=["draft", "serve"])
    ap.add_argument("--root", type=pathlib.Path)
    ap.add_argument("--approve")
    ap.add_argument("--development-task", type=pathlib.Path)
    ap.add_argument("--development-task-sha256")
    args = ap.parse_args()
    if args.development_task is not None:
        configure_development_task(args.development_task, args.development_task_sha256)
    elif args.development_task_sha256 is not None:
        ap.error("task definition and pin required together")
    if args.command == "draft":
        print(json.dumps({"contract": contract(), "approval": digest(encoded(contract()))}, indent=2))
        return
    if not args.root or not args.root.is_absolute():
        ap.error("serve needs an absolute fresh --root")
    worker = Worker(args.root, args.approve)
    try:
        while not worker.done and worker.count < MAX_REQUESTS:
            raw = sys.stdin.buffer.readline(MAX_BYTES * 3 + 1)
            if not raw:
                break
            if len(raw) > MAX_BYTES * 3 or not raw.endswith(b"\n"):
                raise ValueError("request framing limit")
            try:
                result = worker.request(parse(raw))
            except (ValueError, OSError, TypeError) as exc:
                result = {"status": "REFUSED", "error": str(exc), "authority": "NONE"}
                worker.event({"refusal": result, "request_sha256": digest(raw)})
            print(json.dumps(result, ensure_ascii=True), flush=True)
    finally:
        worker.close()


if __name__ == "__main__":
    main()
