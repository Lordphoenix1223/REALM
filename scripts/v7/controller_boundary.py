"""Confined proposal process using the existing candidate sandbox runner.

This is an executable boundary experiment, not native execution authority. The
host owns all tool dispatch; proposals cannot read workspace contents in the
tested Mac profile. Negative metadata lookup is NOT isolated. Runtime reads,
clock and entropy are outside capture, so historical decision reuse is refused.
No model provider is called here. A future host model transport must retain its
actual request/response bytes separately from these local process exchanges.
"""
import json
import os
from pathlib import Path
import platform
import shutil
import sys

import coding_worker as worker


class ProposalProcess(worker.Sandbox):
    """One bounded stdin/stdout exchange; no workspace mount or inherited FDs.

    Reuses Sandbox.execute's timeout, output bounds, closed descriptors, clean
    environment, CPU limits and process-group retirement. Caller code is always
    untrusted. This type has no native verifier or publication conversion.
    """
    def __init__(self, protected):
        self.backend = platform.system()
        self.python = Path(sys.executable).resolve(strict=True)
        self.candidate = Path('/')  # child's cwd, never the private workspace
        self.evidence_channel_guard = False
        protected = [Path(p).resolve(strict=True) for p in protected]
        if not protected:
            raise ValueError('explicit protected objects required')
        if self.backend == 'Darwin':
            app_python = Path(sys.base_prefix).resolve() / 'Resources/Python.app/Contents/MacOS/Python'
            if app_python.is_file():
                self.python = app_python.resolve()
            roots = [Path(sys.prefix).resolve(), Path('/System'), Path('/usr/lib'),
                     Path('/private/var/db/dyld'), Path('/Library/Apple/System/Library'),
                     Path('/opt/homebrew/Cellar')]
            if any(p == r or r in p.parents for p in protected for r in roots):
                raise ValueError('protected object overlaps readable runtime')
            literals = set(self.python.parents)
            if any(p in literals for p in protected):
                raise ValueError('protected object overlaps runtime ancestor')
            rules = ' '.join('(subpath ' + json.dumps(str(p)) + ')' for p in roots)
            exact = ' '.join('(literal ' + json.dumps(str(p)) + ')' for p in literals)
            self.profile = ('(version 1)(deny default)(allow process-exec (literal '
                            + json.dumps(str(self.python)) + '))(allow file-read* '
                            + rules + ' ' + exact + ' (literal "/dev/null") (literal "/dev/urandom"))'
                            + '(allow sysctl-read)(deny network*)(deny process-fork)')
            self.prefix = ['/usr/bin/sandbox-exec', '-p', self.profile, str(self.python), '-I', '-B']
        elif self.backend == 'Linux':
            bwrap = shutil.which('bwrap')
            if not bwrap or not str(self.python).startswith('/usr/'):
                raise ValueError('bubblewrap and /usr Python required')
            roots = [Path('/usr'), Path('/bin'), Path('/lib'), Path('/lib64')]
            if any(p == r.resolve() or r.resolve() in p.parents for p in protected for r in roots):
                raise ValueError('protected object overlaps readable runtime')
            self.prefix = [bwrap, '--unshare-all', '--die-with-parent', '--new-session',
                           '--cap-drop', 'ALL', '--clearenv', '--ro-bind', '/usr', '/usr']
            for name in ('/bin', '/lib', '/lib64'):
                if Path(name).is_symlink():
                    self.prefix += ['--symlink', os.readlink(name), name]
                elif Path(name).exists():
                    self.prefix += ['--ro-bind', name, name]
            self.prefix += ['--proc', '/proc', '--dev', '/dev', '--chdir', '/',
                            str(self.python), '-I', '-B']
            self.profile = 'bubblewrap:unshare-all,readonly-runtime,no-workspace,no-private-tmp'
        else:
            raise ValueError('unsupported controller isolation platform')

    def propose(self, program, context):
        """Retain actual bytes before interpreting or dispatching proposals."""
        raw = worker.encoded(context)
        code, stdout, stderr = self.execute(program, raw)
        capture = {'status': 'REFUSE', 'authority': 'NONE', 'platform': self.backend,
                   'profile': self.profile, 'interpreter_sha256': worker.digest(self.python.read_bytes()),
                   'controller_sha256': worker.digest(program.encode()),
                   'stdin_hex': raw.hex(), 'stdout_hex': stdout.hex(), 'stderr_hex': stderr.hex(),
                   'exit': code, 'causal_reuse': 'REFUSE', 'native_same_run': 'NOT_ESTABLISHED',
                   'complete_observation_admission': 'REFUSE',
                   'observation_limit': 'Darwin negative-lookup oracle; Linux boundary not qualified; runtime/clock/entropy outside capture'}
        if code != 0:
            return None, capture
        try:
            request = worker.parse(stdout)
        except (ValueError, UnicodeError):
            return None, capture
        if not isinstance(request, dict):
            return None, capture
        capture['status'] = 'PROPOSAL_ONLY'
        return request, capture

    def require_qualified(self):
        # This route has no qualified environment on either platform. In
        # particular Darwin reports ENOENT for a nonexistent protected path
        # before Seatbelt denies metadata access. Do not sign this as complete.
        raise ValueError('REFUSE: proposal isolation has no qualified native observation boundary')


def dispatch(process, program, context, broker):
    """Reuse the actual existing Worker broker; no alternative effect engine."""
    proposal, capture = process.propose(program, context)
    if proposal is None:
        return None, capture
    # Worker checks schema/path authorization before effects and records actual
    # successful tool results. This diagnostic also retains rejected proposals.
    try:
        result = broker.request(proposal)
    except ValueError as error:
        capture.update(status='REFUSE', tool_error=str(error))
        return None, capture
    capture.update(status='DEVELOPMENT_TOOL_RESULT', tool_result_hex=worker.encoded(result).hex())
    return result, capture
