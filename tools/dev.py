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
    p.add_argument('lane', choices=['fast','test','sensitive','coding','v7'])
    p.add_argument('--output', type=Path, default=Path('realm-validation'))
    a = p.parse_args()
    run(sys.executable, '-B', 'tools/check_release.py')
    run(sys.executable, '-B', 'scripts/check_source_manifest.py')
    run(sys.executable, '-B', 'tools/check_public_safety.py')
    for folder in ['tools', 'examples', 'integrations', 'scripts']:
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
    run(sys.executable, '-B', '-m', 'unittest', 'tools.test_coding_safety', 'tools.test_release_manifest', '-v')
    run(sys.executable, '-B', '-m', 'unittest', 'tools.test_ci_paths',
        'scripts.test_public_sync', 'scripts.test_audit_local_source', '-v')
    if a.lane == 'fast':
        print('PASS: fast source/fixture checks; native verification NOT_RUN')
        return
    if a.lane == 'v7':
        run('cargo', 'build', '--locked', '-p', 'realm-cli', '-p', 'realm-v6',
            '--bin', 'realm', '--bin', 'coding_submission_probe')
        target = Path(ENV.get('CARGO_TARGET_DIR', str(ROOT/'target')))
        if not target.is_absolute(): target = ROOT/target
        ENV['REALM_BINARY'] = str(target/'debug/realm')
        ENV['REALM_NATIVE_BINARY'] = str(target/'debug/coding_submission_probe')
        ENV['PYTHONPATH'] = str(ROOT/'scripts/v7')
        modules = ['test_native_input_contract', 'test_native_subtasks', 'test_coding_task_verifier',
                   'test_native_publication_entrypoint', 'test_receiver_project_history', 'test_coding_native_run']
        if sys.platform.startswith('linux') and os.geteuid() != 0:
            modules.append('test_native_attempt_retention')
        run(sys.executable, '-B', '-m', 'unittest',
            *['scripts/v7/'+name+'.py' for name in modules], '-v')
        print('PASS: V7 contract/refusal/interface checks; native guest qualification NOT_RUN; authority NONE')
        return
    run('cargo', 'build', '--locked', '-p', 'realm-artifact', '--bin', 'realm-artifact')
    target = Path(ENV.get('CARGO_TARGET_DIR', str(ROOT/'target')))
    if not target.is_absolute(): target = ROOT/target
    ENV['REALM_CHECKER'] = str(target/'debug/realm-artifact')
    if a.lane == 'coding':
        run(sys.executable, '-B', 'examples/coding/run.py', '--checker', ENV['REALM_CHECKER'],
            '--output', a.output.resolve(), '--disposable-replay')
        print('PASS: bounded coding mechanics; production INCOMPLETE/NONE')
        return
    rust_args = []
    if sys.platform.startswith('linux') and os.geteuid() != 0:
        # These four real metadata fixtures chown to another UID and mknod.
        # Do not grant CI additional privileges or turn their failures into passes.
        restricted = [
            'coding_fence::tests::optional_device_is_removed_by_held_inode_and_never_admitted',
            'coding_fence::tests::altered_vendor_device_metadata_refuses',
            'coding_fence::tests::held_device_directory_and_inode_substitutions_refuse',
            'coding_fence::tests::extra_reachable_objects_refuse_before_optional_device_removal',
        ]
        print('NOT_RUN: root-only device/ownership component fixtures:', *restricted, sep='\n', flush=True)
        rust_args = ['--', *[arg for name in restricted for arg in ('--skip', name)]]
    run('cargo', 'test', '--locked', '--workspace', *rust_args)
    run(sys.executable, '-B', '-m', 'unittest', 'discover', '-s', 'tools', '-v')
    if (ROOT/'integrations/python/tests').exists():
        run(sys.executable, '-B', '-m', 'unittest', 'discover', '-s',
            'integrations/python/tests', '-v')
    if a.lane == 'sensitive':
        output = a.output.resolve()
        output.mkdir(exist_ok=False)
        run('cargo', 'fmt', '--all', '--check')
        run('cargo', 'clippy', '--locked', '--workspace', '--all-targets', '--', '-D', 'warnings')
        run('cargo', 'check', '--locked', '--manifest-path', 'crates/realm-artifact/fuzz/Cargo.toml', '--bins')
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
