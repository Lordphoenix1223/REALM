#!/usr/bin/env python3
"""Offline audit of a pinned development transcript; NEVER a REALM verifier.

No candidate execution, host mutation, publication capability or .realm output.
Checks exported statements against a separately supplied contract and custody pins.
Does not authenticate execution, prove containment, or establish effect completeness.
"""
import argparse
import hashlib
import json
import os
import pathlib
import random
import stat

FILES = {"totals.py", "report.py", "test_totals.py"}
MAX_BYTES = 32768
MAX_JOURNAL = 32 * 1024 * 1024


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


def sha(data):
    return hashlib.sha256(data).hexdigest()


def pairs(items):
    result = {}
    for key, value in items:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def parse(data):
    return json.loads(data, object_pairs_hook=pairs,
                      parse_constant=lambda _: (_ for _ in ()).throw(ValueError("nonfinite JSON")))


def require(condition, message):
    if not condition:
        raise ValueError(message)


def file_identity(value):
    return (value.st_dev, value.st_ino, value.st_mode, value.st_nlink,
            value.st_uid, value.st_gid, value.st_size, value.st_mtime_ns, value.st_ctime_ns)


def read_regular(path, limit, *, dir_fd=None, private=True):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=dir_fd)
    try:
        info = os.fstat(fd)
        require(stat.S_ISREG(info.st_mode) and
                (not private or (info.st_nlink == 1 and info.st_uid == os.getuid())),
                "unowned, linked or nonregular evidence")
        require(info.st_size <= limit, "evidence size limit")
        parts = []
        remaining = info.st_size
        while remaining:
            # The fstat size is bounded above. Prefer one allocation; still
            # handle short reads, and independently reread every byte below.
            part = os.read(fd, remaining)
            require(bool(part), "short evidence read")
            parts.append(part)
            remaining -= len(part)
        require(not os.read(fd, 1), "evidence grew during read")
        # Linux inode timestamps can stay equal across a same-jiffy overwrite.
        # Recheck bytes too; metadata alone is not a stable-read witness.
        data = parts[0] if len(parts) == 1 else b"".join(parts)
        del parts
        os.lseek(fd, 0, os.SEEK_SET)
        offset = 0
        while offset < len(data):
            part = os.read(fd, min(len(data) - offset, 65536))
            require(bool(part) and part == data[offset:offset + len(part)],
                    "evidence bytes changed during read")
            offset += len(part)
        require(not os.read(fd, 1), "evidence grew during reread")
        require(file_identity(info) == file_identity(os.fstat(fd)) ==
                file_identity(os.stat(path, follow_symlinks=False, dir_fd=dir_fd)),
                "evidence identity changed during read")
        return data
    finally:
        os.close(fd)


def journal_lines(raw, *, has_cr=True):
    """Yield bytes.splitlines() boundaries without retaining all line copies."""
    start = 0
    while start < len(raw):
        lf = raw.find(b"\n", start)
        end = len(raw) if lf == -1 else lf
        if has_cr:
            cr = raw.find(b"\r", start, end)
            if cr != -1:
                end = cr
        yield raw[start:end]
        start = end + 1
        if raw[end:end + 2] == b"\r\n":
            start += 1


def oracle(records):
    # Separate implementation: never imports the worker or candidate.
    if type(records) is not list:
        return None
    buckets = {}
    for item in records:
        if type(item) is not dict or set(item) != {"amount", "category"}:
            return None
        if type(item["amount"]) is not int or type(item["category"]) is not str:
            return None
        category = item["category"].strip()
        if not category:
            return None
        buckets[category] = buckets.get(category, 0) + item["amount"]
    ordered = [{"category": name, "amount": buckets[name]} for name in sorted(buckets)]
    return {"net": sum(item["amount"] for item in ordered), "totals": ordered}


def cases(seed):
    require(type(seed) is int and 0 <= seed < 2 ** 128, "invalid checker seed")
    fixed = [[], [{"category": " B ", "amount": 4}, {"category": "A", "amount": -7},
                  {"category": "B", "amount": -9}], {}, [None],
             [{"category": "A", "amount": True}], [{"category": " ", "amount": 1}],
             [{"category": "A", "amount": "1"}], [{"category": 3, "amount": 1}],
             [{"category": "A", "amount": 1, "extra": 1}]]
    rng = random.Random(seed)
    for _ in range(8):
        fixed.append([{"category": rng.choice(["A", "z", " B ", "é"]),
                       "amount": rng.randint(-10000, 10000)}
                      for _ in range(rng.randint(1, 16))])
    return fixed


def checked_result(result, interpreter):
    require(result["interpreter_sha256"] == interpreter, "interpreter pin differs")
    observations = result["development_conformance"]
    require(type(observations) is dict and
            set(observations) == {"candidate_read", "candidate_write", "protected_read",
                                  "protected_write", "network"} and
            all(value is True for value in observations.values()), "conformance statements differ")
    inputs = cases(result["seed"])
    rows = result["independent_cases"]
    require(type(rows) is list and len(rows) == len(inputs), "checker case count differs")
    passes = []
    for index, (given, recorded) in enumerate(zip(inputs, rows)):
        require(type(recorded["case"]) is int and recorded["case"] == index and
                canonical(recorded["input"]) == canonical(given), "checker input differs")
        answer = oracle(given)
        require(canonical(recorded["expected"]) == canonical(answer), "oracle statement differs")
        require(type(recorded["exit"]) is int and type(recorded["stdout"]) is str and
                type(recorded["stderr"]) is str, "invalid process observation")
        require(len(recorded["stdout"].encode()) <= MAX_BYTES and
                len(recorded["stderr"].encode()) <= MAX_BYTES, "output limit differs")
        if answer is None:
            passed = recorded["exit"] == 2
        else:
            try:
                passed = recorded["exit"] == 0 and canonical(parse(recorded["stdout"])) == canonical(answer)
            except (ValueError, TypeError):
                passed = False
        require(recorded["passed"] is passed, "checker verdict contradicts observations")
        passes.append(passed)
    tests = result["candidate_tests"]
    require(tests["trusted_oracle"] is False and type(tests["exit"]) is int,
            "candidate tests cannot become the oracle")
    passed = all(passes) and tests["exit"] == 0
    require(result["passed"] is passed, "aggregate verdict contradicts observations")
    return passed, sum(passes)


def audit(root, contract, contract_pin, worker_pin, interpreter_pin, head_pin):
    require(sha(canonical(contract)) == contract_pin, "contract pin differs")
    require(contract["authority"] == "NONE" and set(contract["files"]) == FILES and
            set(contract["baseline"]) == FILES and contract["max_file_bytes"] == MAX_BYTES and
            contract["max_requests"] == 128, "unsupported development contract")
    raw = read_regular(root / "events.jsonl", MAX_JOURNAL)
    require(raw.endswith(b"\n"), "torn journal")
    # A terminated binary journal has LF, CR or CRLF line boundaries. Count
    # before parsing so oversized journals retain the original refusal order.
    has_cr = b"\r" in raw
    line_count = raw.count(b"\n")
    if has_cr:
        line_count += raw.count(b"\r") - raw.count(b"\r\n")
    require(1 <= line_count <= 128, "journal length differs")
    previous = "0" * 64
    state = dict(contract["baseline"])
    last_check = False
    finished = False
    checks = []
    for index, line in enumerate(journal_lines(raw, has_cr=has_cr)):
        require(len(line) <= 2 * 1024 * 1024, "journal line limit")
        row = parse(line)
        require(set(row) == {"sequence", "previous", "event", "sha256"}, "journal fields differ")
        claim = row.pop("sha256")
        require(type(row["sequence"]) is int and row["sequence"] == index and
                row["previous"] == previous and sha(canonical(row)) == claim,
                "journal chain differs")
        previous = claim
        event = row["event"]
        if index == 0:
            require(event["authority"] == "NONE" and event["worker_sha256"] == worker_pin and
                    event["contract_sha256"] == contract_pin and
                    canonical(event["contract"]) == canonical(contract), "genesis pins differ")
            continue
        require(not finished, "event after finish")
        if "refusal" in event:
            require(event["refusal"]["status"] == "REFUSED" and
                    event["refusal"]["authority"] == "NONE", "invalid refusal")
            # A refused check may have invalidated a previous check; refuse to retain it.
            last_check = False
            continue
        require(set(event) == {"request", "result", "before", "after"}, "event fields differ")
        require(event["before"] == state, "unexplained preceding file change")
        request, result = event["request"], event["result"]
        tool = request.get("tool")
        schemas = {"list": {"tool"}, "read": {"tool", "path"},
                   "write": {"tool", "path", "text"}, "check": {"tool"}, "finish": {"tool"}}
        require(tool in schemas and set(request) == schemas[tool], "unsupported recorded tool")
        if tool in ("read", "write"):
            require(request["path"] in FILES, "path outside contract")
        if tool == "write":
            text = request["text"]
            require(type(text) is str and len(text.encode()) <= MAX_BYTES, "invalid write")
            state[request["path"]] = sha(text.encode())
            require(result == {"written": request["path"]}, "write acknowledgment differs")
            last_check = False
        elif tool == "read":
            require(type(result["text"]) is str and sha(result["text"].encode()) == state[request["path"]],
                    "read content differs")
        elif tool == "list":
            require(result["files"] == state and result["task"] == contract["description"],
                    "list content differs")
        elif tool == "check":
            last_check, passed_count = checked_result(result, interpreter_pin)
            checks.append({"sequence": index, "passed": last_check, "passed_cases": passed_count,
                           "total_cases": 17})
        else:
            require(last_check and result == {"status": "DEVELOPMENT_TASK_CHECKED", "files": state,
                    "authority": "NONE", "realm_artifact": None, "history_complete": False,
                    "controller_inside_guest": False}, "finish lacks exact current check")
            finished = True
        require(event["after"] == state, "unexplained resulting file change")
    require(previous == head_pin, "external journal head differs")
    candidate = root / "candidate"
    require(not candidate.is_symlink() and set(os.listdir(candidate)) == FILES,
            "candidate file set differs")
    actual = {name: sha(read_regular(candidate / name, MAX_BYTES)) for name in FILES}
    require(actual == state, "physical candidate differs from transcript")
    return {"status": "DEVELOPMENT_TRANSCRIPT_CHECKED", "finished": finished,
            "authority": "NONE", "realm_artifact": None, "history_complete": False,
            "execution_authenticated": False, "containment_qualified": False,
            "checks": checks, "files": actual, "journal_head": previous, "events": line_count}


def verify_final_state(root, expected):
    """Reopen disposable results without following links; no application authority."""
    require(type(expected) is dict and set(expected) == FILES and
            all(type(v) is str and len(v) == 64 and not set(v) - set('0123456789abcdef')
                for v in expected.values()), 'exact expected three-file hashes required')
    fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        info = os.fstat(fd)
        require(info.st_uid == os.getuid() and stat.S_IMODE(info.st_mode) == 0o700,
                'private disposable directory required')
        require(set(os.listdir(fd)) == FILES, 'disposable file set differs')
        for name in sorted(FILES):
            before = os.stat(name, dir_fd=fd, follow_symlinks=False)
            require(stat.S_IMODE(before.st_mode) == 0o600, 'disposable file mode differs')
            raw = read_regular(name, MAX_BYTES, dir_fd=fd)
            require(file_identity(before) == file_identity(os.stat(name, dir_fd=fd, follow_symlinks=False)),
                    'disposable file replaced during verification')
            require(sha(raw) == expected[name], 'disposable file bytes differ')
        require(set(os.listdir(fd)) == FILES, 'disposable file set changed')
        require(file_identity(info) == file_identity(os.fstat(fd)) == file_identity(os.stat(root, follow_symlinks=False)),
                'disposable directory identity changed')
    finally:
        os.close(fd)
    return {'status': 'PASS_DISPOSABLE_FINAL_STATE', 'authority': 'NONE', 'files': expected}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=pathlib.Path, required=True)
    parser.add_argument("--contract", type=pathlib.Path)
    parser.add_argument("--final-state", action="store_true")
    parser.add_argument("--expected-files", help="exact JSON map for disposable final-state verification")
    for name in ("contract-sha256", "worker-sha256", "interpreter-sha256", "journal-head"):
        parser.add_argument("--" + name)
    args = parser.parse_args()
    try:
        require(args.root.is_absolute() and not args.root.is_symlink(), "absolute unlinked root required")
        if args.final_state:
            result = verify_final_state(args.root, parse(args.expected_files))
            print(json.dumps(result))
            return
        require(args.contract is not None and all([args.contract_sha256, args.worker_sha256,
                args.interpreter_sha256, args.journal_head]), "contract and all independent pins required")
        contract = parse(read_regular(args.contract, MAX_JOURNAL))
        result = audit(args.root, contract, args.contract_sha256, args.worker_sha256,
                       args.interpreter_sha256, args.journal_head)
    except (ValueError, OSError, KeyError, TypeError) as error:
        print(json.dumps({"status": "REFUSED", "error": str(error), "authority": "NONE"}))
        raise SystemExit(2)
    print(json.dumps(result, indent=2))
    raise SystemExit(0 if result["finished"] else 3)


if __name__ == "__main__":
    main()
