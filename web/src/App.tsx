import {
  type ChangeEvent,
  type DragEvent,
  type KeyboardEvent,
  useCallback,
  useEffect,
  useMemo,
  useRef,
  useState,
} from 'react';
import './App.css';
import { type CompatibilityResult, type PatchReport } from './lib/patchEngine';
import type { WorkerRequest, WorkerResponse } from './lib/workerProtocol';
import { extractExeIconUrl } from './lib/exeIcon';

type InspectResponse = Extract<WorkerResponse, { type: 'inspect_result' }>;
type ApplyResponse = Extract<WorkerResponse, { type: 'apply_result' }>;
type CounterStatus = 'idle' | 'loading' | 'ready' | 'error' | 'unconfigured';

const COUNTER_API_BASE = import.meta.env.VITE_COUNTER_API_BASE?.trim().replace(/\/+$/, '') ?? '';
const ASSET_BASE = import.meta.env.BASE_URL;
const REPO_URL = 'https://github.com/Skezza/pm99-skezmod-patcher';
const EMPTY_ICON_URL = `${ASSET_BASE}file-upload-icon.svg`;

function parseCount(value: unknown): number | null {
  if (typeof value === 'number' && Number.isFinite(value)) {
    return value;
  }

  if (typeof value === 'string' && value.trim() !== '') {
    const parsed = Number(value);
    if (Number.isFinite(parsed)) {
      return parsed;
    }
  }

  return null;
}

function downloadFile(blob: Blob, fileName: string): void {
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement('a');
  anchor.href = url;
  anchor.download = fileName;
  anchor.click();
  URL.revokeObjectURL(url);
}

function App() {
  const workerRef = useRef<Worker | null>(null);
  const fileInputRef = useRef<HTMLInputElement | null>(null);
  const requestIdRef = useRef(1);
  const pendingRef = useRef(
    new Map<
      number,
      {
        resolve: (value: WorkerResponse) => void;
        reject: (reason: Error) => void;
      }
    >(),
  );

  const [loadedFile, setLoadedFile] = useState<File | null>(null);
  const [loadedBytes, setLoadedBytes] = useState<ArrayBuffer | null>(null);
  const [loadedIconUrl, setLoadedIconUrl] = useState<string | null>(null);
  const [compatibility, setCompatibility] = useState<CompatibilityResult | null>(null);
  const [applyReport, setApplyReport] = useState<PatchReport | null>(null);
  const [reportUrl, setReportUrl] = useState<string | null>(null);
  const [statusText, setStatusText] = useState('');
  const [errorText, setErrorText] = useState<string | null>(null);
  const [isBusy, setIsBusy] = useState(false);
  const [dragActive, setDragActive] = useState(false);
  const [patchCount, setPatchCount] = useState<number | null>(null);
  const [counterStatus, setCounterStatus] = useState<CounterStatus>('idle');

  const counterUrl = useCallback((path: string): string | null => {
    if (!COUNTER_API_BASE) {
      return null;
    }
    return `${COUNTER_API_BASE}${path}`;
  }, []);

  const loadPatchCount = useCallback(async (): Promise<number | null> => {
    const url = counterUrl('/api/patch-count');
    if (!url) {
      setCounterStatus('unconfigured');
      return null;
    }

    setCounterStatus('loading');
    const response = await fetch(url);
    if (!response.ok) {
      throw new Error(`Counter fetch failed (${response.status})`);
    }

    const payload = (await response.json()) as { count?: unknown };
    const count = parseCount(payload.count);
    if (count === null) {
      throw new Error('Counter response missing numeric count');
    }

    setPatchCount(count);
    setCounterStatus('ready');
    return count;
  }, [counterUrl]);

  const incrementPatchCount = useCallback(async (): Promise<number | null> => {
    const url = counterUrl('/api/patch-success');
    if (!url) {
      return null;
    }

    const response = await fetch(url, { method: 'POST' });
    if (!response.ok) {
      throw new Error(`Counter increment failed (${response.status})`);
    }

    const payload = (await response.json()) as { count?: unknown };
    const count = parseCount(payload.count);
    if (count === null) {
      throw new Error('Counter increment response missing numeric count');
    }

    setPatchCount(count);
    setCounterStatus('ready');
    return count;
  }, [counterUrl]);

  useEffect(() => {
    const worker = new Worker(new URL('./worker/patchWorker.ts', import.meta.url), { type: 'module' });
    const pendingMap = pendingRef.current;
    workerRef.current = worker;

    worker.onmessage = (event: MessageEvent<WorkerResponse>) => {
      const message = event.data;
      const pending = pendingMap.get(message.id);
      if (!pending) {
        return;
      }
      pendingMap.delete(message.id);

      if (message.type === 'error') {
        pending.reject(new Error(message.error));
        return;
      }

      pending.resolve(message);
    };

    worker.onerror = (event: ErrorEvent) => {
      const error = new Error(event.message || 'Worker runtime error');
      pendingMap.forEach(({ reject }) => reject(error));
      pendingMap.clear();
    };

    return () => {
      worker.terminate();
      workerRef.current = null;
      pendingMap.clear();
    };
  }, []);

  useEffect(() => {
    return () => {
      if (reportUrl) {
        URL.revokeObjectURL(reportUrl);
      }
    };
  }, [reportUrl]);

  useEffect(() => {
    return () => {
      if (loadedIconUrl) {
        URL.revokeObjectURL(loadedIconUrl);
      }
    };
  }, [loadedIconUrl]);

  useEffect(() => {
    if (!COUNTER_API_BASE) {
      setCounterStatus('unconfigured');
      return;
    }

    void loadPatchCount().catch(() => {
      setCounterStatus('error');
    });
  }, [loadPatchCount]);

  const callWorker = useCallback((request: Omit<WorkerRequest, 'id'>): Promise<WorkerResponse> => {
    const worker = workerRef.current;
    if (!worker) {
      throw new Error('Patch worker is not available');
    }

    const id = requestIdRef.current;
    requestIdRef.current += 1;

    return new Promise((resolve, reject) => {
      pendingRef.current.set(id, { resolve, reject });
      worker.postMessage({ ...request, id }, [request.bytes]);
    });
  }, []);

  const runPreflight = useCallback(
    async (fileName: string, bytes: ArrayBuffer) => {
      setIsBusy(true);
      setErrorText(null);
      setStatusText('Checking compatibility...');

      try {
        const response = (await callWorker({
          type: 'inspect',
          fileName,
          bytes: bytes.slice(0),
        })) as InspectResponse;

        setCompatibility(response.compatibility);
        setStatusText(
          response.compatibility.ok
            ? response.compatibility.alreadyPatched
              ? 'This file already includes SkezMod Patch 0.1.'
              : 'Ready to apply SkezMod Patch 0.1.'
            : 'This is not a supported MANAGPRE.EXE build.',
        );
      } catch (error) {
        const message = error instanceof Error ? error.message : 'Compatibility check failed unexpectedly';
        setCompatibility(null);
        setErrorText(message);
        setStatusText('Compatibility check failed.');
      } finally {
        setIsBusy(false);
      }
    },
    [callWorker],
  );

  const loadFile = useCallback(
    async (file: File) => {
      setLoadedFile(file);
      setApplyReport(null);
      setCompatibility(null);
      setErrorText(null);
      setLoadedIconUrl(null);

      if (reportUrl) {
        URL.revokeObjectURL(reportUrl);
        setReportUrl(null);
      }

      const bytes = await file.arrayBuffer();
      setLoadedBytes(bytes);
      try {
        setLoadedIconUrl(extractExeIconUrl(bytes));
      } catch {
        setLoadedIconUrl(null);
      }
      await runPreflight(file.name, bytes);
    },
    [reportUrl, runPreflight],
  );

  const onFileInputChange = async (event: ChangeEvent<HTMLInputElement>) => {
    const file = event.target.files?.[0];
    if (!file) {
      return;
    }

    await loadFile(file);
    event.target.value = '';
  };

  const onDrop = async (event: DragEvent<HTMLDivElement>) => {
    event.preventDefault();
    setDragActive(false);

    if (isBusy) {
      return;
    }

    const file = event.dataTransfer.files?.[0];
    if (!file) {
      return;
    }

    await loadFile(file);
  };

  const onDragOver = (event: DragEvent<HTMLDivElement>) => {
    event.preventDefault();
    setDragActive(true);
  };

  const onDragLeave = (event: DragEvent<HTMLDivElement>) => {
    event.preventDefault();
    setDragActive(false);
  };

  const openFilePicker = useCallback(() => {
    if (isBusy) {
      return;
    }

    fileInputRef.current?.click();
  }, [isBusy]);

  const onDropZoneKeyDown = useCallback((event: KeyboardEvent<HTMLDivElement>) => {
    if (isBusy) {
      return;
    }

    if (event.key === 'Enter' || event.key === ' ') {
      event.preventDefault();
      openFilePicker();
    }
  }, [isBusy, openFilePicker]);

  const applyPatch = async () => {
    if (!loadedFile || !loadedBytes || !compatibility?.ok) {
      return;
    }

    setIsBusy(true);
    setErrorText(null);
    setStatusText('Applying SkezMod Patch 0.1...');

    try {
      const response = (await callWorker({
        type: 'apply',
        fileName: loadedFile.name,
        bytes: loadedBytes.slice(0),
      })) as ApplyResponse;

      const patchedBlob = new Blob([response.outputBytes], { type: 'application/octet-stream' });
      downloadFile(patchedBlob, 'MANAGPRE.skezmod.exe');

      const reportBlob = new Blob([JSON.stringify(response.report, null, 2)], {
        type: 'application/json',
      });
      if (reportUrl) {
        URL.revokeObjectURL(reportUrl);
      }
      setReportUrl(URL.createObjectURL(reportBlob));

      setApplyReport(response.report);
      setStatusText('Done. Your patched EXE should download immediately.');

      void incrementPatchCount().catch(() => {
        setCounterStatus('error');
      });
    } catch (error) {
      const message = error instanceof Error ? error.message : 'Patch failed unexpectedly';
      setErrorText(message);
      setStatusText('Patch failed.');
    } finally {
      setIsBusy(false);
    }
  };

  const versionLabel = useMemo(() => {
    return compatibility?.variantLabel ?? '';
  }, [compatibility]);

  const visibleReasons = useMemo(() => {
    return compatibility?.reasons.filter((reason) => reason !== 'Signature checks passed.') ?? [];
  }, [compatibility]);

  const counterLabel = useMemo(() => {
    if (patchCount !== null) {
      return patchCount.toLocaleString();
    }

    if (counterStatus === 'unconfigured') {
      return 'Not configured';
    }

    if (counterStatus === 'error') {
      return 'Unavailable';
    }

    return 'Loading...';
  }, [counterStatus, patchCount]);

  return (
    <main className="app-shell">
      <section className="app-card">
        <header className="hero">
          <p className="eyebrow">Unofficial Premier Manager Ninety Nine Production Patchset</p>
          <div className="logo-lockup" role="img" aria-label="Premier Manager Ninety Nine SkezMod">
            <div
              className="logo-cover"
              style={{
                backgroundImage: `linear-gradient(180deg, rgba(8, 14, 27, 0.38), rgba(8, 14, 27, 0.75)), url(${ASSET_BASE}keegan-cover-cropped.png)`,
              }}
            />
            <div className="logo-copy">
              <img className="logo-tag-image" src={`${ASSET_BASE}skezmod-logo-cut.png`} alt="SkezMod logo" />
            </div>
          </div>
          <p className="hero-sub">The worlds first self-service PM99 patch application toolkit.</p>
          <p className="patch-counter">
            <strong>PM99's patched worldwide:</strong> {counterLabel}
          </p>
        </header>

        <section className="panel">
          <h2>1. Load Binary</h2>
          <div
            className={`drop-zone ${dragActive ? 'is-active' : ''} ${loadedFile ? 'has-file' : ''} ${isBusy ? 'is-busy' : ''}`}
            onDrop={onDrop}
            onDragOver={onDragOver}
            onDragLeave={onDragLeave}
            onClick={openFilePicker}
            onKeyDown={onDropZoneKeyDown}
            role="button"
            tabIndex={isBusy ? -1 : 0}
            aria-disabled={isBusy}
            aria-label="Drop MANAGPRE.EXE here or click to choose a file"
          >
            <input
              ref={fileInputRef}
              type="file"
              accept=".exe"
              hidden
              onChange={onFileInputChange}
            />
            {loadedFile ? (
              <div className="drop-zone-content loaded">
                <div className="drop-zone-iconFrame" aria-hidden="true">
                  {loadedIconUrl ? (
                    <img className="drop-zone-iconImage" src={loadedIconUrl} alt="" aria-hidden="true" />
                  ) : (
                    <span className="drop-zone-iconFallback">?</span>
                  )}
                </div>
                <div className="drop-zone-copy">
                  <p className="drop-zone-fileline">{loadedFile.name}</p>
                  {compatibility ? <p className="drop-zone-meta">{versionLabel}</p> : null}
                </div>
              </div>
            ) : (
              <div className="drop-zone-content empty">
                <div className="drop-zone-iconFrame" aria-hidden="true">
                  <img className="drop-zone-iconImage drop-zone-iconImage--empty" src={EMPTY_ICON_URL} alt="" aria-hidden="true" />
                </div>
                <div className="drop-zone-copy">
                  <p className="drop-zone-title">Drop MANAGPRE.EXE here</p>
                  <p className="drop-zone-meta">or click to choose a file</p>
                </div>
              </div>
            )}
          </div>
        </section>

        <section className="panel">
          <h2>2. Apply SkezMod Patch 0.1</h2>
          <div className="option-list" role="group" aria-label="Patch options">
            <label>
              <input type="checkbox" checked readOnly disabled />
              <span>Stars Patch RC2</span>
            </label>
          </div>

          <button
            type="button"
            className="primary"
            onClick={applyPatch}
            disabled={isBusy || !compatibility?.ok}
          >
            {isBusy ? 'Processing...' : 'Apply'}
          </button>

          {reportUrl ? (
            <a className="report-link" href={reportUrl} download="skezmod_report.json">
              Download patch report (JSON)
            </a>
          ) : null}
        </section>

        <section className="panel diagnostics">
          {statusText ? <p className="status-line">{statusText}</p> : null}
          {visibleReasons.length ? (
            <ul>
              {visibleReasons.map((reason) => (
                <li key={reason}>{reason}</li>
              ))}
            </ul>
          ) : null}
          {errorText ? <p className="error-line">{errorText}</p> : null}
          {applyReport ? <p>Applied patch operations: {applyReport.patchCount}</p> : null}
        </section>

        <footer className="app-footer">
          <a href={REPO_URL} target="_blank" rel="noreferrer">
            Source on GitHub
          </a>
        </footer>
      </section>
    </main>
  );
}

export default App;
