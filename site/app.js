/* This UI selects frozen native Rust results. It never verifies uploaded inputs. */
'use strict';
const $ = id => document.getElementById(id);
const scenarioButtons = [...document.querySelectorAll('[data-scenario]')];
const reportNames = ['intact','intact-execution','tampered','missing','clean-content','clean-execution','hidden-content','hidden-execution'];
let reports, outside, pair, manifest, bytes, revealed = false, changed = true;
const say = message => { $('announcement').textContent = message; };

function useTheme(mode) {
  document.documentElement.dataset.theme = mode;
  $('theme').setAttribute('aria-label', `Switch to ${mode === 'dark' ? 'light' : 'dark'} theme`);
}
try { const stored = localStorage.getItem('realm-theme'); if (['light','dark'].includes(stored)) useTheme(stored); } catch (_) { /* Storage can be unavailable; system preference still works. */ }
$('theme').addEventListener('click', () => {
  const mode = document.documentElement.dataset.theme || (matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light');
  const next = mode === 'dark' ? 'light' : 'dark'; useTheme(next);
  try { localStorage.setItem('realm-theme', next); } catch (_) { /* No persistence required. */ }
});

async function json(name) {
  const response = await fetch(`evidence/${name}.json`);
  if (!response.ok) throw new Error('Saved evidence unavailable');
  return response.json();
}
async function artifact(name) {
  const response = await fetch(`evidence/${name}.realm`);
  if (!response.ok) throw new Error('Prepared artifact unavailable');
  return new Uint8Array(await response.arrayBuffer());
}
function showReport(name) {
  $('report-select').value = name;
  $('report-json').textContent = JSON.stringify(reports[name], null, 2);
  $('download-report').href = `evidence/${name}.json`;
}
function chooseScenario(name, updateAddress = true) {
  if (!['intact','tampered','hidden'].includes(name)) name = 'hidden';
  scenarioButtons.forEach(button => button.setAttribute('aria-pressed', String(button.dataset.scenario === name)));
  ['intact','tampered','hidden'].forEach(key => { $(`${key}-panel`).hidden = key !== name; });
  showReport(name === 'hidden' ? 'hidden-content' : name === 'tampered' && !changed ? 'intact' : name);
  if (updateAddress) history.replaceState(null, '', `#${name}`);
  say(`${name === 'hidden' ? 'Hidden action' : name === 'intact' ? 'Intact artifact' : 'Changed artifact'}: prepared native results selected. Not live verification.`);
}
function reveal() {
  revealed = !revealed;
  $('outside-evidence').hidden = !revealed;
  $('reveal').setAttribute('aria-expanded', String(revealed));
  $('reveal').textContent = revealed ? 'Hide the outside observation ↙' : 'Reveal the outside observation ↗';
  $('hidden-event').className = revealed ? 'is-revealed' : 'unrevealed';
  $('hidden-event-title').textContent = revealed ? 'Temporarily change protected.txt' : 'A moment missing from the records';
  $('hidden-event-detail').textContent = revealed ? `${outside.hidden_intermediate} → ${outside.hidden_final}. The supplied record omits this.` : 'What do the final files leave out?';
  say(revealed ? 'The independent experimental harness reopened a temporary forbidden write. REALM does not detect it. Artifact content stays VALID and execution authorization INCOMPLETE for both.' : 'Outside observation hidden. Saved checker results remain unchanged.');
}
function chooseByte(useChanged) {
  changed = useChanged;
  const report = reports[changed ? 'tampered' : 'intact'];
  $('original-byte').setAttribute('aria-pressed', String(!changed));
  $('changed-byte').setAttribute('aria-pressed', String(changed));
  $('tamper-status').textContent = report.status;
  $('tamper-status').className = `large-status ${changed ? 'status-invalid' : 'status-valid'}`;
  $('tamper-diagnostic').textContent = report.diagnostic;
  $('tamper-diagnostic').className = changed ? 'diagnostic' : '';
  $('tamper-explanation').textContent = changed ? 'The native checker rejected this inconsistent payload. You are reading its saved report.' : 'The original recorded content passed. This still says nothing about complete observation.';
  $('byte-label').textContent = changed ? 'One payload byte differs' : 'Original payload byte';
  const difference = bytes.intact.findIndex((value, i) => value !== bytes.tampered[i]);
  const hex = value => `0x${value.toString(16).padStart(2, '0')}`;
  $('byte-before').textContent = hex(bytes.intact[difference]);
  $('byte-after').textContent = hex((changed ? bytes.tampered : bytes.intact)[difference]);
  $('byte-offset').textContent = `Byte offset ${difference}. These are the actual prepared artifact bytes.`;
  $('byte-artifact').href = `evidence/${changed ? 'tampered' : 'intact'}.realm`;
  showReport(changed ? 'tampered' : 'intact');
  say(`${changed ? 'Changed' : 'Original'} prepared input selected: saved Rust checker result ${report.status}. Not a live check.`);
}

async function start() {
  scenarioButtons.forEach(button => { button.disabled = true; });
  const [loadedReports, observer, paired, pins, original, modified] = await Promise.all([
    Promise.all(reportNames.map(json)), json('outside-observation'), json('paired-result'), json('manifest'), artifact('intact'), artifact('tampered')
  ]);
  reports = Object.fromEntries(reportNames.map((name, i) => [name, loadedReports[i]]));
  outside = observer; pair = paired; manifest = pins; bytes = {intact:original,tampered:modified};
  // Fail closed if the prepared evidence doesn't match this walkthrough's contract.
  if (manifest.mode !== 'PREPARED_NATIVE_RESULTS_NOT_LIVE_VERIFICATION' || !pair.artifacts_byte_identical || pair.rows.length !== 2 || pair.rows.some(row => row.task_test_exit !== 0) || outside.hidden_intermediate !== 'changed' || outside.hidden_final !== 'original') throw new Error('Prepared experiment contract changed');
  for (const [name, report] of Object.entries(reports)) {
    if (report.schema !== 'realm.artifact-check.v1' || report.checks.execution_authorization !== 'NOT_CHECKED') throw new Error('Unexpected saved report');
    const expected = ['intact','clean-content','hidden-content'].includes(name) ? 'VALID' : name === 'tampered' ? 'INVALID' : 'INCOMPLETE';
    if (report.status !== expected) throw new Error('Saved result differs from the explained scenario');
  }
  if (original.length !== modified.length || original.reduce((count, value, i) => count + (value !== modified[i]), 0) !== 1) throw new Error('Expected one actual altered byte');
  $('clean-final').textContent = outside.clean_final;
  $('hidden-final').textContent = outside.hidden_final;
  $('outside-intermediate').textContent = outside.hidden_intermediate;
  $('outside-final').textContent = outside.hidden_final;
  $('pair-content').textContent = reports['hidden-content'].status;
  $('pair-execution').textContent = reports['hidden-execution'].status;
  $('pair-hash').textContent = pair.rows[0].artifact_sha256;
  $('intact-hash').textContent = manifest.files['intact.realm'];
  $('intact-status').textContent = reports.intact.status;
  $('intact-integrity').textContent = reports.intact.checks.artifact_integrity;
  $('intact-content').textContent = reports.intact.checks.referenced_content;
  $('intact-observation').textContent = reports.intact.checks.observation_completeness;
  $('intact-execution').textContent = reports['intact-execution'].status;
  chooseByte(true);
  scenarioButtons.forEach((button, i) => {
    button.disabled = false;
    button.addEventListener('click', () => chooseScenario(button.dataset.scenario));
    button.addEventListener('keydown', event => {
      const movements = {ArrowRight:(i+1)%3,ArrowLeft:(i+2)%3,Home:0,End:2};
      if (event.key in movements) { event.preventDefault(); const next = scenarioButtons[movements[event.key]]; next.focus(); chooseScenario(next.dataset.scenario); }
    });
  });
  $('reveal').addEventListener('click', reveal);
  $('original-byte').addEventListener('click', () => chooseByte(false));
  $('changed-byte').addEventListener('click', () => chooseByte(true));
  $('go-hidden').addEventListener('click', () => { chooseScenario('hidden'); scenarioButtons[2].focus(); });
  $('report-select').addEventListener('change', event => showReport(event.target.value));
  addEventListener('hashchange', () => {
    const name = location.hash.slice(1);
    if (['intact','tampered','hidden'].includes(name)) chooseScenario(name, false);
  });
  $('loading').hidden = true; $('evidence-app').hidden = false;
  chooseScenario(location.hash.slice(1) || 'hidden', false);
}
$('copy').addEventListener('click', async () => {
  try { await navigator.clipboard.writeText($('run-commands').textContent); $('copy').textContent = 'Copied'; say('Local experiment commands copied.'); }
  catch (_) { $('copy').textContent = 'Select the commands above to copy'; say('Clipboard unavailable. Select the displayed commands to copy them.'); }
});
start().catch(() => {
  $('loading').className = 'loading error';
  $('loading').textContent = 'The saved evidence could not be loaded. No result is established. Reload, or read the reproducible case study on GitHub.';
});
