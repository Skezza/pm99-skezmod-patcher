import createCore from '../assets/pm99-core.js';

export async function loadCore(print) {
  // Only the compiled application is fetched. The C program's files live in memory.
  // Loading bytes also works when a static host serves .wasm as application/octet-stream.
  const response = await fetch(new URL('../assets/pm99-core.wasm', import.meta.url));
  if (!response.ok) throw new Error('The site could not load the patcher engine.');
  const module = await createCore({
    wasmBinary: await response.arrayBuffer(),
    print,
    printErr: print,
  });
  return {
    fs: module.FS,
    exportPackage: module.cwrap('pm99_web_export', 'number', ['number']),
    buildPackage: module.cwrap('pm99_web_build', 'number', []),
    error: module.cwrap('pm99_web_error', 'string', []),
  };
}
