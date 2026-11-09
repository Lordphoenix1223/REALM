# Reproduce a fresh autonomous development solve

Use the existing `run_development_vertical.py --codex-agent` entry point. It
starts an ephemeral supported Codex CLI session **after** task/source freeze,
sends only public requirements, broken/current files, the runtime contract and
observed feedback, then submits its generated source through the existing
Worker, sandbox, independent referee/auditor, encoder and receiver. It permits
at most two generations, each with a180-second local process response deadline.
Server-side cancellation/elapsed time after a client timeout is not observed. No precomputed solution,
retained actions or chat transcript is an input to this mode.

Requirements: supported macOS Seatbelt, Python/Rust, an offline Cargo dependency
cache, installed `codex` CLI and existing **ChatGPT** login (`codex login status`).
The adapter strips OpenAI API keys and inherited Codex routing/session variables,
ignores user config, and disables shell, apps, plugins, memory and multi-agent
features. It does not sign in, add permissions, buy credits or fall back to API
billing. Inference consumes existing plan usage; dollar cost is not reported.
Model output is three complete source strings. The controller schedules real
write/check/finish tools; the model does not choose arbitrary tools or effects.
A failed check permits one repair; finish still requires the exact current tree
to pass. Candidate code/tests cannot fork, use the network or write files.

These three unrelated task definitions, baselines and oracle inputs were frozen
in `0758de329b226fd3971432548d0c558c62f34bf1` before any solver invocation. The
solving CLI receives no acceptance inputs, oracle source, prior solutions or
inherited conversation. They are engineer-authored tasks, not an independent
third-party benchmark or proof of absence from model pretraining. Distinct
Worker/auditor oracle algorithms are fixed in source; both remain user-writable
host software and grant no production authority.

From clean frozen combined source `68b70b0e385260a3332e7d41d23ba497142f9542`
(or its evidence-only successor), this command runs the suite without a chat:

```sh
python3 - <<'PY'
from pathlib import Path
import subprocess, tempfile
root = Path(tempfile.mkdtemp(prefix='realm-fresh-independent-'))
pins = {
 'interval-union': ('259583d473e33f993f5685ea4a7ee6c08bff3d7c38174855d185839304ff4215', 'e7140c5b58ce5eda4bbe1ddadb55ef6879159d0e5cb0d1da4a14820cb0b4cf95'),
 'dependency-order': ('6570cfc35882b00cec5ae9f94a482afc8af05595843c647db1e2dea87d3fba4d', 'c7c2d1ab67d104aef72d22c87cce9325abf5e0d00fb0ad65a23fe34350e871b0'),
 'unicode-runs': ('a766b4a834113e4c15bf6cc286bc0721222e34f06240e2cf7c835b06a2b3522b', 'dff8541ec979eade405f0c3049f1aa2febbf4e3839cd5c4314930aa3eea654c8')}
for name, (task_pin, definition_pin) in pins.items():
    cmd = ['python3', '-B', 'scripts/v7/run_development_vertical.py',
           '--output', str(root/name), '--target', str(root/'cargo'),
           '--task', f'scripts/v7/fresh_tasks/{name}.task.json',
           '--task-sha256', task_pin,
           '--development-task', f'scripts/v7/fresh_tasks/{name}.definition.json',
           '--development-task-sha256', definition_pin,
           '--codex-agent', '--disposable-replay', '--verify-integrated-interfaces']
    result = subprocess.run(cmd)
    print(name, 'driver exit', result.returncode, 'records', root/name)
print('Preserve every run directory, including FAILURE.json and planner failures:', root)
PY
```

The model is the installed CLI's default; its resolved model identifier was not
exposed in retained events. CLI version/hash, exact argv, prompts, schema,
answers, event logs, token usage when reported, source pins, artifacts and
verifier decisions are retained. Fresh inference is stochastic and service
availability varies; reproducing the procedure does not guarantee an identical
solution, artifact or success. Empty/cold offline dependency caches fail rather
than downloading. On another machine, provision the required cached toolchain
before the bounded experiment. No privileged/remote host or VM is required.

All success is **development mechanics**. Receiver authority must remain NONE;
canonical native publication and protected application are not authorized.
Disposable replay is explicit test authorization, not receiver ACCEPT. See
`evidence/v7/repeatable-autonomous-20261030/README.md` for the actual nine-launch
history and final-source compatibility checks. Official CLI interface:
https://learn.chatgpt.com/docs/non-interactive-mode
