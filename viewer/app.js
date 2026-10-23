'use strict';
let token, original, current, currentName = 'valid.realm', report, generation = 0;
const element = id => document.getElementById(id);
function text(tag, content, className) {
  const node = document.createElement(tag);
  node.textContent = content;
  if (className) node.className = className;
  return node;
}
function items(id, rows, empty) {
  const target = element(id); target.replaceChildren();
  if (!rows.length) rows = [{label:empty, detail:'The artifact may omit activity. Absence of a record is not proof of absence.'}];
  for (const row of rows) {
    const node = text('div', row.label, 'item');
    node.append(text('small', row.detail)); target.append(node);
  }
}
function render(value) {
  report = value;
  element('status').textContent = value.status;
  element('status').dataset.status = value.status;
  element('diagnostic').textContent = value.diagnostic;
  element('authority-status').textContent = value.checks.execution_authorization;
  element('raw').textContent = JSON.stringify(value, null, 2);
  const grid = element('proof-grid'); grid.replaceChildren();
  for (const [label, key] of [['Artifact integrity','artifact_integrity'],['Referenced content','referenced_content'],['Observation completeness','observation_completeness']]) {
    const result = value.checks[key]; const card = text('div', '', 'proof');
    card.append(text('span', label), text('strong', result, ['PASS','COMPLETE'].includes(result) ? 'pass' : result === 'FAIL' ? 'fail' : 'unknown')); grid.append(card);
  }
  const data = value.metadata || {};
  items('activity', (data.observations || []).map(x => ({label:x.kind + ' · ' + x.target, detail:'Recorded observation: ' + x.id})), 'No readable activity established.');
  items('unknowns', (data.unknown_effects || []).map(x => ({label:x.kind, detail:x.reason})), 'Complete process observation is not established.');
  element('references').textContent = JSON.stringify({inputs:data.inputs,outputs:data.outputs,evidence:data.evidence,proposed_effects:data.proposed_effects,reported_verification:data.reported_verification}, null, 2);
}
async function check(bytes, name) {
  const mine = ++generation; current = bytes; currentName = name;
  element('artifact-name').textContent = name;
  element('status').textContent = 'CHECKING'; element('status').dataset.status = '';
  report = null; element('proof-grid').replaceChildren(); element('activity').replaceChildren(); element('unknowns').replaceChildren(); element('raw').textContent = ''; element('references').textContent = ''; element('diagnostic').textContent = 'Running the Rust checker locally…';
  try {
    const response = await fetch('/api/check', {method:'POST',headers:{'X-Realm-Token':token},body:bytes});
    const result = await response.json();
    if (!response.ok) throw Error(result.error || 'Checker unavailable');
    if (mine === generation) render(result.report);
  } catch (error) {
    if (mine !== generation) return;
    element('status').textContent = 'NO RESULT'; element('status').dataset.status = '';
    element('diagnostic').textContent = error.message;
    element('proof-grid').replaceChildren(); element('activity').replaceChildren(); element('unknowns').replaceChildren();
    element('raw').textContent = ''; element('references').textContent = '';
  }
}
async function sample(name) {
  const response = await fetch('/samples/' + name + '.realm');
  if (!response.ok) throw Error('Sample unavailable');
  original = new Uint8Array(await response.arrayBuffer());
  document.querySelectorAll('[data-case]').forEach(button => button.classList.toggle('selected', button.dataset.case === name));
  await check(original.slice(), name + '.realm');
}
document.querySelectorAll('[data-case]').forEach(button => button.addEventListener('click', () => sample(button.dataset.case).catch(showError)));
function showError(error) { element('diagnostic').textContent = error.message; }
element('upload').addEventListener('change', async event => {
  const file = event.target.files[0]; if (!file) return;
  if (file.size > 64 * 1024 * 1024) return showError(Error('Maximum artifact size is 64 MiB.'));
  original = new Uint8Array(await file.arrayBuffer());
  document.querySelectorAll('[data-case]').forEach(button => button.classList.remove('selected'));
  await check(original.slice(), file.name);
});
element('mutate').addEventListener('click', () => { if (!current || !current.length) return; const altered = current.slice(); altered[altered.length-1] ^= 1; check(altered, currentName + ' · changed byte'); });
element('reset').addEventListener('click', () => { if (original) check(original.slice(), 'restored.realm'); });
element('download').addEventListener('click', () => {
  if (!report) return;
  const url = URL.createObjectURL(new Blob([JSON.stringify(report,null,2)], {type:'application/json'}));
  const link = document.createElement('a'); link.href = url; link.download = 'realm-check.json'; link.click(); setTimeout(() => URL.revokeObjectURL(url), 1000);
});
fetch('/session').then(response => response.json()).then(session => {token = session.token; return sample('valid');}).catch(showError);
