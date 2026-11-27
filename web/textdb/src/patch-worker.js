import { rewriteStarsId } from './stars.js';
import { collectRenderingFiles } from './rendering.js';
import { makePackage } from './package.js';
import { loadCore } from './wasm-core.js';

async function stage(fs, root, entries) {
  for (const { path, file } of entries) {
    const target = `${root}/${path}`;
    fs.mkdirTree(target.slice(0, target.lastIndexOf('/')));
    fs.writeFile(target, new Uint8Array(await file.arrayBuffer()));
  }
}

function* collect(fs, root, directory = '') {
  for (const name of fs.readdir(root + directory).sort()) {
    if (name === '.' || name === '..') continue;
    const path = `${directory}/${name}`;
    const full = root + path;
    if (fs.isDir(fs.stat(full).mode)) yield* collect(fs, root, path);
    else yield { path: path.slice(1), bytes: fs.readFile(full) };
  }
}

self.onmessage = async ({ data: { mode, entries, fixStars, renderingFiles } }) => {
  const log = [];
  const print = (line) => {
    if (!line.trim()) return;
    log.push(line.slice(0, 1000));
    if (log.length > 150) log.shift();
    if (/^\[\d\/\d\]|^ALL OK|^SELF-TEST PASSED/.test(line)) {
      self.postMessage({ type: 'progress', text: line });
    }
  };
  try {
    const core = await loadCore(print);
    const isExport = mode === 'export';
    const fromGame = isExport || mode === 'play';
    const render = isExport ? [] : await collectRenderingFiles(renderingFiles);
    await stage(core.fs, fromGame ? '/game' : '/package', entries);
    const check = rc => {
      if (rc !== 0) throw new Error(core.error() || `The patcher stopped with code ${rc}.`);
    };
    if (fromGame) {
      check(core.exportPackage(Number(entries.some(({ path }) => path === 'DBDAT/FECHCONV.30'))));
      if (!isExport) core.fs.rename('/result', '/package');
    }
    if (!isExport) check(core.buildPackage());
    const files = [...collect(core.fs, '/result')];
    if (!files.length) throw new Error('The patcher produced no files.');
    if (!isExport && fixStars) {
      const eq = files.find(({ path }) => path === 'DBDAT/EQ98030.FDI');
      if (!eq) throw new Error('The build did not contain EQ98030.FDI.');
      rewriteStarsId(eq.bytes);
      print('Stars: club ID 9899 in the output database.');
    }
    files.push(...render);
    self.postMessage({
      type: 'result',
      zip: makePackage(files),
      paths: files.map(({ path }) => path),
      log,
    });
  } catch (error) {
    self.postMessage({ type: 'error', text: error.message, log });
  }
};
