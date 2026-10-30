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
import socket
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
    return {"schema": "realm.coding-development.v1", "description": DESCRIPTION,
            "files": list(FILES), "baseline": {k: digest(v.encode()) for k, v in BASELINE.items()},
            "max_file_bytes": MAX_BYTES, "max_requests": MAX_REQUESTS,
            "tools": ["list", "read", "write", "check", "finish"],
            "authority": "NONE", "runtime": "kernel-child-development-only"}


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
            child.stdin.write(data)
            child.stdin.close()
            for name in streams:
                selector.register(getattr(child, name), selectors.EVENT_READ, name)
            deadline = time.monotonic() + 3
            while selector.get_map():
                if time.monotonic() > deadline:
                    raise ValueError("candidate timeout")
                for key, _ in selector.select(timeout=0.1):
                    chunk = os.read(key.fileobj.fileno(), 4096)
                    if not chunk:
                        selector.unregister(key.fileobj)
                    else:
                        streams[key.data].extend(chunk)
                        if len(streams[key.data]) > MAX_BYTES:
                            raise ValueError("candidate output limit")
            code = child.wait(timeout=max(0.01, deadline - time.monotonic()))
            return code, bytes(streams["stdout"]), bytes(streams["stderr"])
        finally:
            # Kill descendants even on successful return, including children holding pipes.
            try:
                os.killpg(child.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            child.wait()
            selector.close()
            child.stdout.close()
            child.stderr.close()


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
probe=socket.socket();probe.settimeout(.5)
deny('network',lambda:probe.connect(('127.0.0.1',PORT)))
probe.close()
print(json.dumps(results))
"""
    code = "CANDIDATE=" + repr(candidate) + "\nSENTINEL=" + repr(str(sentinel)) + "\n" + code
    before = sentinel.read_bytes()
    # An unused port makes ECONNREFUSED indistinguishable from a sandbox denial.
    # Keep a real controller listener alive throughout the bounded probe.
    with socket.socket() as listener:
        listener.bind(('127.0.0.1', 0)); listener.listen(1); listener.setblocking(False)
        code = 'PORT=' + str(listener.getsockname()[1]) + '\n' + code
        code_status, out, err = sandbox.execute(code, b"")
        result = parse(out) if code_status == 0 else {}
        try:
            connection, _ = listener.accept()
        except BlockingIOError:
            pass
        else:
            connection.close(); result['network'] = False
    if result != dict.fromkeys(["candidate_read", "candidate_write", "protected_read", "protected_write", "network"], True) or sentinel.read_bytes() != before:
        raise ValueError("REFUSE: development sandbox conformance failed: " + err.decode(errors="replace"))
    return result


def expected(records):
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
        totals[key] = totals.get(key, 0) + amount
    return {"totals": [{"category": k, "amount": totals[k]} for k in sorted(totals)],
            "net": sum(totals.values())}


def check(sandbox, seed):
    rng = random.Random(seed)
    cases = [[], [{"category": " B ", "amount": 4}, {"category": "A", "amount": -7},
                  {"category": "B", "amount": -9}], {}, [None],
             [{"category": "A", "amount": True}], [{"category": " ", "amount": 1}],
             [{"category": "A", "amount": "1"}], [{"category": 3, "amount": 1}],
             [{"category": "A", "amount": 1, "extra": 1}]]
    for _ in range(8):
        cases.append([{"category": rng.choice(["A", "z", " B ", "é"]),
                       "amount": rng.randint(-10000, 10000)} for _ in range(rng.randint(1, 16))])
    rows = []
    for n, inputs in enumerate(cases):
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
    def __init__(self, root, approval, *, evidence_channel_guard=False):
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
        for name, content in BASELINE.items():
            self.write(name, content.encode())
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
    args = ap.parse_args()
    if args.command == "draft":
        print(json.dumps({"contract": contract(), "approval": digest(encoded(contract()))}, indent=2))
        return
    if not args.root or not args.root.is_absolute():
        ap.error("serve needs an absolute fresh --root")
    worker = Worker(args.root, args.approve, evidence_channel_guard=(platform.system() == "Linux"))
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
    try:
        main()
    except (ValueError, OSError) as error:
        raise SystemExit("REFUSE: " + str(error))
