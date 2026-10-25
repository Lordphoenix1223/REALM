"""Preview subprocess adapter for realm.artifact-check.v1; Rust is authoritative."""
from dataclasses import dataclass, field
from enum import Enum
import json
import math
from pathlib import Path
import subprocess
from typing import Any

SCHEMA = 'realm.artifact-check.v1'


class Status(str, Enum):
    VALID = 'VALID'
    INVALID = 'INVALID'
    INCOMPLETE = 'INCOMPLETE'
    UNSUPPORTED = 'UNSUPPORTED'
    IO_ERROR = 'IO_ERROR'


EXIT_CODES = {Status.VALID: 0, Status.INVALID: 1, Status.INCOMPLETE: 3,
              Status.UNSUPPORTED: 4, Status.IO_ERROR: 5}


class CheckerError(RuntimeError):
    """Adapter/transport failure, not a verification decision."""


class ProtocolError(CheckerError):
    """Unrecognized, malformed or contradictory native output; no report granted."""


class CheckerUnavailable(CheckerError):
    pass


class CheckerTimeout(CheckerError):
    pass


class NativeCommandError(CheckerError):
    def __init__(self, operation: str, returncode: int, stderr: str):
        self.operation, self.returncode, self.stderr = operation, returncode, stderr
        super().__init__(f'{operation} exited {returncode}: {stderr}')


@dataclass(frozen=True)
class Checks:
    artifact_integrity: str
    referenced_content: str
    observation_completeness: str
    execution_authorization: str


@dataclass(frozen=True)
class Report:
    schema: str
    checker_version: str
    status: Status
    diagnostic: str
    checks: Checks
    _json: str = field(repr=False)

    @property
    def metadata(self) -> dict[str, Any] | None:
        return self.to_dict()['metadata']

    def to_dict(self) -> dict[str, Any]:
        """An independent copy of the exact native JSON document, including extras."""
        return json.loads(self._json)


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('duplicate JSON key')
        result[key] = value
    return result


def _reject_constant(value):
    raise ValueError('non-finite JSON constant: '+value)


def _report(stdout: bytes, returncode: int) -> Report:
    try:
        raw = json.loads(stdout, object_pairs_hook=_unique_object,
                         parse_constant=_reject_constant)
        if not isinstance(raw, dict) or raw['schema'] != SCHEMA:
            raise ValueError('unrecognized schema')
        status = Status(raw['status'])
        if returncode != EXIT_CODES[status]:
            raise ValueError('status and exit code disagree')
        for name in ['checker_version', 'diagnostic']:
            if not isinstance(raw[name], str):
                raise ValueError('invalid '+name)
        if not raw['checker_version']:
            raise ValueError('missing checker version')
        checks = raw['checks']
        if checks['artifact_integrity'] not in {'PASS', 'FAIL', 'NOT_CHECKED'}:
            raise ValueError('unrecognized integrity level')
        if checks['referenced_content'] not in {'COMPLETE', 'INCOMPLETE', 'FAIL', 'NOT_CHECKED'}:
            raise ValueError('unrecognized content level')
        if checks['observation_completeness'] != 'UNKNOWN' or checks['execution_authorization'] != 'NOT_CHECKED':
            raise ValueError('authority claim outside supported inspection contract')
        if status == Status.VALID and (checks['artifact_integrity'], checks['referenced_content']) != ('PASS', 'COMPLETE'):
            raise ValueError('VALID lacks successful supported content checks')
        if raw['metadata'] is not None and not isinstance(raw['metadata'], dict):
            raise ValueError('invalid metadata')
        return Report(raw['schema'], raw['checker_version'], status, raw['diagnostic'],
                      Checks(**{k: checks[k] for k in Checks.__annotations__}),
                      json.dumps(raw, ensure_ascii=True, allow_nan=False))
    except (ValueError, TypeError, KeyError, UnicodeError) as error:
        raise ProtocolError(f'invalid Rust report: {error}') from error


class Checker:
    """Explicit trusted executable; no shell, download, auto-build or Python verifier.

    Input paths name local files. This adapter is not a sandbox and does not
    authenticate the executable or freeze files against concurrent mutation.
    """
    def __init__(self, executable: str | Path, *, timeout: float = 30):
        if not math.isfinite(timeout) or timeout <= 0:
            raise ValueError('timeout must be finite and positive')
        try:
            self.executable = Path(executable).expanduser().resolve(strict=True)
            if not self.executable.is_file():
                raise OSError('checker must be a regular executable file')
        except OSError as error:
            raise CheckerUnavailable(str(error)) from error
        self.timeout = timeout

    def _run(self, operation: str, *args: str):
        try:
            return subprocess.run([str(self.executable), operation, *args],
                                  stdin=subprocess.DEVNULL, capture_output=True,
                                  timeout=self.timeout, check=False, shell=False)
        except subprocess.TimeoutExpired as error:
            raise CheckerTimeout(f'{operation} exceeded {self.timeout}s; no result established') from error
        except OSError as error:
            raise CheckerUnavailable(str(error)) from error

    def _check(self, operation, artifact, require_execution=False):
        # Absolute paths cannot be mistaken for CLI flags, even for a file named --json.
        args = [str(Path(artifact).absolute()), '--json']
        if require_execution:
            args.append('--require-execution')
        result = self._run(operation, *args)
        if result.returncode not in EXIT_CODES.values():
            raise NativeCommandError(operation, result.returncode,
                                     result.stderr.decode('utf-8', 'replace'))
        return _report(result.stdout, result.returncode)

    def inspect(self, artifact: str | Path) -> Report:
        return self._check('inspect', artifact)

    def verify(self, artifact: str | Path, *, require_execution: bool = False) -> Report:
        return self._check('verify', artifact, require_execution)

    def record_observations(self, run_id: str, before: str | Path, after: str | Path,
                            log: str | Path, output: str | Path) -> Report:
        """Import supplied files via Rust; output must be new. No observer is trusted.

        Returns the actual Rust --require-execution report for the imported file.
        Native import failures (including usage=2 and I/O=5) retain their exit code
        in NativeCommandError; no JSON verification report is fabricated for them.
        """
        if not isinstance(run_id, str) or not 1 <= len(run_id.encode('utf-8')) <= 256:
            raise ValueError('run_id must contain 1..256 UTF-8 bytes')
        result = self._run('record', run_id, *[
            str(Path(p).absolute()) for p in [before, after, log, output]])
        if result.returncode:
            raise NativeCommandError('record', result.returncode,
                                     result.stderr.decode('utf-8', 'replace'))
        return self.verify(output, require_execution=True)
