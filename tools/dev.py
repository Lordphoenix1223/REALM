#!/usr/bin/env python3
"""Bounded contributor checks. These do not qualify execution authority."""
import argparse
import os
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
ENV = dict(os.environ)
for key, value in {'CARGO_BUILD_JOBS':'2', 'CARGO_PROFILE_DEV_DEBUG':'0',
                   'CARGO_PROFILE_TEST_DEBUG':'0', 'CARGO_INCREMENTAL':'0'}.items():
    ENV.setdefault(key, value)

def run(*args):
    print('+', *map(str, args), flush=True)
    subprocess.run(list(map(str, args)), cwd=ROOT, env=ENV, check=True)

def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('lane', choices=['fast','test','sensitive'])
    p.add_argument('--output', type=Path, default=Path('realm-validation'))
    a = p.parse_args()
    run(sys.executable, '-B', 'tools/check_release.py')
    for folder in ['tools', 'examples', 'integrations']:
        for file in (ROOT/folder).rglob('*.py'):
            compile(file.read_bytes(), str(file), 'exec')
    static_tests = ['all_frozen_files_and_source_inputs_match_their_hashes',
        'paired_artifacts_and_separate_outside_observation',
        'tampered_control_is_exactly_one_actual_byte',
        'html_assets_links_and_fragment_targets',
        'deployment_is_static_only_and_preserves_exact_evidence']
    # Name every fast check explicitly: native parity must never silently skip.
    run(sys.executable, '-B', '-m', 'unittest', *[
        'tools.test_walkthrough.WalkthroughTests.test_'+name for name in static_tests])
    if (ROOT/'integrations/python/tests/test_protocol.py').exists():
        run(sys.executable, '-B', '-m', 'unittest', 'discover', '-s',
            'integrations/python/tests', '-p', 'test_protocol.py', '-v')
    if a.lane == 'fast':
        print('PASS: fast source/fixture checks; native verification NOT_RUN')
        return
    run('cargo', 'build', '--locked', '-p', 'realm-artifact', '--bin', 'realm-artifact')
    target = Path(ENV.get('CARGO_TARGET_DIR', str(ROOT/'target')))
    if not target.is_absolute(): target = ROOT/target
    ENV['REALM_CHECKER'] = str(target/'debug/realm-artifact')
    run('cargo', 'test', '--locked', '-p', 'realm-artifact', '--lib', '--bin',
        'realm-artifact', '--test', 'toolkit_cli')
    run(sys.executable, '-B', '-m', 'unittest', 'discover', '-s', 'tools', '-v')
    if (ROOT/'integrations/python/tests').exists():
        run(sys.executable, '-B', '-m', 'unittest', 'discover', '-s',
            'integrations/python/tests', '-v')
    if a.lane == 'sensitive':
        output = a.output.resolve()
        output.mkdir(exist_ok=False)
        run('cargo', 'clippy', '--locked', '-p', 'realm-artifact', '--lib', '--bin',
            'realm-artifact', '--test', 'toolkit_cli', '--', '-D', 'warnings')
        run(sys.executable, 'examples/counterexample/run.py', '--checker',
            ENV['REALM_CHECKER'], '--output', output/'counterexample')
        run(sys.executable, 'benchmarks/run.py', '--checker', ENV['REALM_CHECKER'],
            '--output', output/'benchmark')
        if (ROOT/'integrations/python/run_matrix.py').exists():
            run(sys.executable, 'integrations/python/run_matrix.py', '--checker',
                ENV['REALM_CHECKER'], '--output', output/'integration')
        print('Evidence retained:', output)
    print('PASS:', a.lane, 'regression checks; execution qualification NOT_ESTABLISHED')

if __name__ == '__main__':
    try:
        main()
    except (subprocess.CalledProcessError, OSError) as error:
        sys.exit(str(error))
