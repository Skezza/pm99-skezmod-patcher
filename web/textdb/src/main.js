// Page wiring. The worker reads selected files locally.
import { captureEntries } from './manifest.js';
import { checkFiles, pickWanted, summarise, verdictFor } from './verify.js';
import { pickRenderingFiles } from './rendering.js';
import { pickPackage } from './package.js';

const $ = (id) => document.getElementById(id);
const els = {
  dropzone: $('dropzone'),
  pickFolder: $('pick-folder'),
  pickFiles: $('pick-files'),
  folderInput: $('folder-input'),
  filesInput: $('files-input'),
  summary: $('selection-summary'),
  progress: $('hash-progress'),
  progressText: $('hash-status'),
  verdict: $('verdict'),
  checklist: $('checklist'),
  checklistBody: $('checklist-body'),
  countLine: $('capture-count'),
  fixStars: $('fix-stars'),
};

const STATUS_LABEL = {
  match: { cls: 'ok', icon: '✓', text: 'Found, matches stock' },
  'wrong-size': { cls: 'bad', icon: '✗', text: 'Found, but the size is wrong (not read)' },
  'wrong-hash': { cls: 'bad', icon: '✗', text: 'Found, but does not match (other edition or damaged)' },
  missing: { cls: 'bad', icon: '✗', text: 'Missing (required)' },
  'not-provided': { cls: 'neutral', icon: '–', text: 'Not provided (optional)' },
};

const VERDICT_CLASS = {
  nothing: 'verdict--neutral',
  incomplete: 'verdict--warn',
  unsupported: 'verdict--bad',
  supported: 'verdict--ok',
};

let runCounter = 0;
let renderingFiles = [];
let gameFiles = [];
let cdFile;
const exportJob = patchJob('export');
const buildJob = patchJob('build');
const playJob = patchJob('play');

function patchJob(mode) {
  const button = $(`${mode}-package`);
  const status = $(`${mode}-status`);
  const save = $(`${mode}-save`);
  const details = $(`${mode}-details`);
  const report = details.querySelector('pre');
  let entries;
  let worker;
  let url;

  function clearResult() {
    if (url) URL.revokeObjectURL(url);
    url = undefined;
    save.removeAttribute('href');
    save.hidden = true;
    details.open = false;
    details.hidden = true;
    report.textContent = '';
  }

  function showReport(lines, open) {
    report.textContent = lines.join('\n');
    details.hidden = lines.length === 0;
    details.open = open;
  }

  button.addEventListener('click', () => {
    if (!entries || worker) return;
    if (mode !== 'export' && !renderingFiles) {
      status.textContent = 'Choose valid rendering files or clear the rendering selection.';
      return;
    }
    clearResult();
    status.textContent = mode === 'export' ? 'Exporting and checking the tables…' : 'Checking tables and rebuilding files…';
    button.disabled = true;
    function finish() {
      worker?.terminate();
      worker = undefined;
      button.disabled = false;
    }
    try {
      worker = new Worker(new URL('./patch-worker.js', import.meta.url), { type: 'module' });
      worker.onmessage = ({ data }) => {
        if (data.type === 'progress') {
          status.textContent = data.text;
          return;
        }
        finish();
        showReport(data.log, data.type === 'error');
        if (data.type === 'error') {
          status.textContent = data.text;
          return;
        }
        url = URL.createObjectURL(data.zip);
        save.href = url;
        save.hidden = false;
        status.textContent = mode === 'export'
          ? `${data.paths.length} files ready. The rebuild matched the stock hashes.`
          : `Ready to download: ${data.paths.join(', ')}.`;
      };
      worker.onerror = () => {
        finish();
        status.textContent = 'The browser could not start the patcher engine. Reload the page and try again.';
      };
      worker.postMessage({
        mode, entries,
        fixStars: mode !== 'export' && els.fixStars.checked,
        renderingFiles: mode === 'export' ? [] : renderingFiles,
      });
    } catch (error) {
      finish();
      status.textContent = error.message;
    }
  });

  const select = (newEntries, message = '') => {
    worker?.terminate();
    worker = undefined;
    entries = newEntries;
    clearResult();
    button.disabled = !entries;
    status.textContent = message;
  };
  select.invalidate = () => select(entries, entries ? 'Options changed. Build again to apply them.' : '');
  return select;
}

// ---- rendering -------------------------------------------------------------------

function renderChecklist(rows, summary) {
  els.checklistBody.replaceChildren();
  for (const r of rows) {
    const tr = document.createElement('tr');
    const label = STATUS_LABEL[r.status];

    const tdFile = document.createElement('td');
    const code = document.createElement('code');
    code.textContent = r.path;
    tdFile.append(code);

    const tdStatus = document.createElement('td');
    const badge = document.createElement('span');
    badge.className = `status status--${label.cls}`;
    badge.textContent = `${label.icon} ${label.text}`;
    tdStatus.append(badge);
    if (r.reason) {
      const why = document.createElement('div');
      why.className = 'reason';
      why.textContent = r.reason;
      tdStatus.append(why);
    }

    const tdRole = document.createElement('td');
    tdRole.textContent = r.role;

    const tdFp = document.createElement('td');
    tdFp.className = 'mono';
    tdFp.textContent = r.actual ? `${r.actual.slice(0, 12)}…` : '—';

    tr.append(tdFile, tdStatus, tdRole, tdFp);
    els.checklistBody.append(tr);
  }
  els.checklist.hidden = false;
  els.countLine.textContent =
    `${summary.capturedOk} of ${summary.capturedTotal} captured ` +
    `(required: ${summary.requiredOk} of ${summary.requiredTotal}).`;
}

function renderVerdict(verdict) {
  els.verdict.className = `verdict ${VERDICT_CLASS[verdict.state]}`;
  els.verdict.replaceChildren();
  const title = document.createElement('p');
  title.className = 'verdict__title';
  title.textContent = verdict.title;
  const msg = document.createElement('p');
  msg.className = 'verdict__message';
  msg.textContent = verdict.message;
  els.verdict.append(title, msg);
  if (verdict.details && verdict.details.length) {
    const ul = document.createElement('ul');
    ul.className = 'verdict__list';
    for (const d of verdict.details) {
      const li = document.createElement('li');
      li.textContent = d;
      ul.append(li);
    }
    els.verdict.append(ul);
  }
}

function setProgress(fraction, text) {
  if (fraction === null) {
    els.progress.hidden = true;
    els.progressText.textContent = text || '';
    return;
  }
  els.progress.hidden = false;
  els.progress.value = fraction;
  els.progressText.textContent = text;
}

// ---- choosing files ----------------------------------------------------------------

async function handleFiles(list) {
  const run = ++runCounter;
  const files = [...list];
  const picked = pickWanted(files);
  if (cdFile) picked.set('fechconv', cdFile);
  const total = captureEntries().length;
  exportJob(undefined);
  els.summary.textContent = `${files.length + Number(Boolean(cdFile))} file(s) chosen; ${picked.size} of them are game files this tool reads.`;
  playJob(undefined);
  // Clear the previous result so a stale verdict is never shown beside a new check.
  els.checklist.hidden = true;
  els.checklistBody.replaceChildren();
  els.countLine.textContent = '';
  els.verdict.hidden = false;
  els.verdict.className = 'verdict verdict--neutral';
  els.verdict.replaceChildren();
  const checking = document.createElement('p');
  checking.className = 'verdict__title';
  checking.textContent = 'Checking…';
  els.verdict.append(checking);
  setProgress(0, 'Checking… Nothing is uploaded.');

  const rows = await checkFiles(picked, {
    onFile: ({ index, path }) => {
      if (run !== runCounter) return;
      setProgress(index / total, `Checking ${path} (${index + 1} of ${total}). Nothing is uploaded.`);
    },
    onBytes: ({ path, read, total: size }) => {
      if (run !== runCounter) return;
      const pct = size ? Math.round((read / size) * 100) : 100;
      setProgress(null, `Reading ${path}: ${pct}%`);
    },
  });
  if (run !== runCounter) return; // a newer selection replaced this one

  const summary = summarise(rows);
  const verdict = verdictFor(summary);
  setProgress(null, 'Check finished.');
  renderChecklist(rows, summary);
  renderVerdict(verdict);
  if (summary.canBuild) {
    const entries = rows.filter(({ status }) => status === 'match').map(({ id, path }) => ({ path, file: picked.get(id) }));
    exportJob(entries);
    playJob(entries);
  }
}

/** Walk dropped entries (folders included). Must read dataTransfer synchronously. */
async function filesFromDrop(dataTransfer) {
  const entries = [];
  for (const item of [...dataTransfer.items]) {
    if (item.kind !== 'file') continue;
    const entry = item.webkitGetAsEntry ? item.webkitGetAsEntry() : null;
    if (entry) entries.push(entry);
  }
  if (entries.length === 0) return [...dataTransfer.files];
  const lists = await Promise.all(entries.map(walkEntry));
  return lists.flat();
}

async function walkEntry(entry) {
  if (entry.isFile) {
    return [await new Promise((resolve, reject) => entry.file(resolve, reject))];
  }
  if (entry.isDirectory) {
    const reader = entry.createReader();
    const children = [];
    for (;;) {
      const batch = await new Promise((resolve, reject) => reader.readEntries(resolve, reject));
      if (batch.length === 0) break;
      children.push(...batch);
    }
    const out = [];
    for (const child of children) out.push(...(await walkEntry(child)));
    return out;
  }
  return [];
}

// ---- wiring ------------------------------------------------------------------------

function wire() {
  setProgress(null, '');

  els.pickFolder.addEventListener('click', () => els.folderInput.click());
  els.pickFiles.addEventListener('click', () => els.filesInput.click());
  // Copy the list, then reset the input so choosing the same folder again fires "change".
  const onPick = (e) => {
    const list = [...e.target.files];
    e.target.value = '';
    if (!list.length) return;
    gameFiles = list;
    handleFiles(gameFiles).catch(showFileError);
  };
  els.folderInput.addEventListener('change', onPick);
  els.filesInput.addEventListener('change', onPick);

  const cdInput = $('cd-input');
  const removeCd = $('remove-cd-file');
  $('pick-cd-file').addEventListener('click', () => cdInput.click());
  cdInput.addEventListener('change', () => {
    const file = cdInput.files[0];
    cdInput.value = '';
    if (!file) return;
    cdFile = file;
    removeCd.hidden = false;
    handleFiles(gameFiles).catch(showFileError);
  });
  removeCd.addEventListener('click', () => {
    cdFile = undefined;
    removeCd.hidden = true;
    handleFiles(gameFiles).catch(showFileError);
  });
  function showFileError(error) {
    setProgress(null, `Could not read the selected files: ${error.message}`);
  }

  const packageInput = $('package-input');
  $('pick-package').addEventListener('click', () => packageInput.click());
  packageInput.addEventListener('change', () => {
    const files = [...packageInput.files];
    packageInput.value = '';
    if (!files.length) return;
    try {
      const entries = pickPackage(files);
      buildJob(entries, `${entries.length} package files selected.`);
    } catch (error) {
      buildJob(undefined, error.message);
    }
  });

  els.dropzone.addEventListener('keydown', (e) => {
    if (e.key === 'Enter' || e.key === ' ') {
      e.preventDefault();
      els.folderInput.click();
    }
  });
  for (const type of ['dragenter', 'dragover']) {
    els.dropzone.addEventListener(type, (e) => {
      e.preventDefault();
      els.dropzone.classList.add('dropzone--active');
    });
  }
  for (const type of ['dragleave', 'drop']) {
    els.dropzone.addEventListener(type, () => els.dropzone.classList.remove('dropzone--active'));
  }
  els.dropzone.addEventListener('drop', async (e) => {
    e.preventDefault();
    try {
      gameFiles = await filesFromDrop(e.dataTransfer);
      await handleFiles(gameFiles);
    } catch (error) {
      showFileError(error);
    }
  });

  const invalidateBuilds = () => {
    playJob.invalidate();
    buildJob.invalidate();
  };
  els.fixStars.addEventListener('change', invalidateBuilds);
  const renderInput = $('render-files');
  const clearRender = $('clear-render-files');
  clearRender.addEventListener('click', () => {
    renderInput.value = '';
    renderInput.dispatchEvent(new Event('change'));
    renderInput.focus();
  });
  renderInput.addEventListener('change', event => {
    clearRender.hidden = !renderInput.files.length;
    try {
      renderingFiles = pickRenderingFiles([...event.target.files]);
      $('render-status').textContent = renderingFiles.map(({ path }) => path).join(', ');
    } catch (error) {
      renderingFiles = undefined;
      $('render-status').textContent = error.message;
    }
    invalidateBuilds();
  });
}

wire();
