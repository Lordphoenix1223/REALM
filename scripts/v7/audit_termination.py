"""Reopen development probe termination evidence without granting authority.

The host probe's finally block sends SIGKILL to its owned pidfd. A signal-9
wait status alone cannot identify who sent the signal, so this audit retains
the distinction between observed controller intent and an exclusive cause.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
import tarfile

SOURCE_ROOT = Path(__file__).resolve().parents[2]
LIMIT = 16 * 1024 * 1024


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def need(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def counters(raw: str) -> dict[str, int]:
    return {key: int(value) for key, value in (line.split() for line in raw.splitlines())}


def inspect(archive: Path, expected_sha256: str) -> dict:
    need(re.fullmatch(r'[0-9a-f]{64}', expected_sha256) is not None, 'invalid archive pin')
    need(archive.is_file() and archive.stat().st_size <= LIMIT, 'archive size differs')
    need(sha(archive.read_bytes()) == expected_sha256, 'archive SHA-256 differs')
    with tarfile.open(archive, 'r:gz') as tar:
        members = tar.getmembers()
        names = [member.name for member in members]
        need(len(names) <= 128 and len(names) == len(set(names)), 'archive members differ')
        need(all(member.isfile() and member.size <= LIMIT for member in members), 'unsupported archive member')
        index = {member.name: member for member in members}
        prefix = 'host/' if 'host/probe-result.json' in index else 'run/'

        def read(name: str, maximum: int = 1024 * 1024) -> bytes:
            member = index[prefix + name]
            need(member.size <= maximum, 'oversize record: ' + name)
            stream = tar.extractfile(member)
            need(stream is not None, 'missing record: ' + name)
            data = stream.read(maximum + 1)
            need(len(data) == member.size, 'short record: ' + name)
            return data

        result = json.loads(read('probe-result.json'))
        observations = [json.loads(row) for row in read('resources.jsonl', LIMIT).splitlines()]
        need(observations and result['owned_vmm_wait']['signal'] == 9, 'not a signal-9 probe')
        need(result['payload_received'] is True and result['status'] == 'DEVELOPMENT_RAW_RECEIVED',
             'raw receipt not established')
        need(result['qualification'] == 'NOT_QUALIFIED' and result['authority'] == 'NONE',
             'unexpected authority assertion')
        embedded = next((name for name in ('source/coding_guest_probe.py',
                         'executed-source/scripts/v7/coding_guest_probe.py') if name in index), None)
        source_commit = None
        if embedded:
            need(index[embedded].size <= 1024 * 1024, 'oversize retained probe source')
            source_bytes = tar.extractfile(index[embedded]).read()
            pinned_sha = sha(source_bytes)
            source_origin = embedded
        else:
            pins = json.loads(tar.extractfile(index['source/SOURCE_PINS.json']).read())
            pinned_sha = pins['files']['coding_guest_probe.py']
            source_commit = pins['intended_merge_source']
            need(type(source_commit) is str and re.fullmatch(r'[0-9a-f]{40}', source_commit),
                 'invalid retained source commit')
            try:
                source_bytes = subprocess.check_output(['git', '-C', str(SOURCE_ROOT), 'show',
                    source_commit + ':scripts/v7/coding_guest_probe.py'], stderr=subprocess.PIPE)
            except subprocess.CalledProcessError as error:
                raise ValueError('retained probe Git source unavailable') from error
            need(sha(source_bytes) == pinned_sha, 'retained probe Git source pin differs')
            source_origin = 'git:' + source_commit
        profile = json.loads(read('profile.json'))
        need(profile['driver_sha256'] == pinned_sha, 'retained probe/profile source pin differs')
        need(len(source_bytes) <= 1024 * 1024, 'oversize retained probe source')
        source = source_bytes.decode('utf-8')
        need('signal.pidfd_send_signal(pidfd, signal.SIGKILL)' in source and
             'cleanup_owned_process(root, pid, pidfd, cg, child, result)' in source,
             'controller kill path differs; audit requires review')
        need(not result.get('cleanup_errors'), 'cleanup failed; signal cause unresolved')
        precleanup = json.loads(read('precleanup-process.json')) if prefix + 'precleanup-process.json' in index else None
        need(precleanup is None or precleanup['pid'] == result['owned_vmm_wait']['pid'],
             'precleanup PID differs from reaped VMM')
        observed_oom = []
        for row in observations:
            vmstat = dict(line.split() for line in row.get('/proc/vmstat', []))
            observed_oom.append(int(vmstat['oom_kill']))
            for name, raw in row['files'].items():
                if name.endswith('/memory.events') and raw != 'FileNotFoundError':
                    observed_oom.append(counters(raw)['oom_kill'])
        need(observed_oom, 'no OOM counters retained')
        oom_delta_zero = min(observed_oom) == max(observed_oom) == 0
        return {
            'schema': 'realm.v7-development-termination-audit/v1',
            'authority': 'NONE', 'release_ready': False,
            'archive_sha256': expected_sha256, 'probe_source_sha256': pinned_sha,
            'probe_source_origin': source_origin, 'probe_source_commit': source_commit,
            'raw_received': True, 'wait_signal': 9,
            'precleanup_pidfd_exited': None if precleanup is None else precleanup['pidfd_exited'],
            'observed_oom_counters_zero': oom_delta_zero,
            'resource_observations': len(observations),
            'controller_sigkill_path': 'PINNED_UNCONDITIONAL_CLEANUP',
            'cause': 'CONTROLLER_CLEANUP_SUPPORTED' if precleanup and precleanup['pidfd_exited'] is False
                     else 'UNKNOWN_NO_PRECLEANUP_OBSERVATION',
            'exclusive_sender_proven': False,
            'native_terminal_closure': False,
        }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('archive', type=Path)
    parser.add_argument('--sha256', required=True)
    args = parser.parse_args()
    print(json.dumps(inspect(args.archive, args.sha256), sort_keys=True))


if __name__ == '__main__':
    main()
