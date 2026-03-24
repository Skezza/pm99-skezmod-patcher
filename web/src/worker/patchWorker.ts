/// <reference lib="webworker" />

import { applySkezmodPatch, inspectCompatibility } from '../lib/patchEngine';
import type { WorkerRequest, WorkerResponse } from '../lib/workerProtocol';

const ctx: DedicatedWorkerGlobalScope = self as DedicatedWorkerGlobalScope;

ctx.onmessage = async (event: MessageEvent<WorkerRequest>): Promise<void> => {
  const request = event.data;

  try {
    const bytes = new Uint8Array(request.bytes);

    if (request.type === 'inspect') {
      const compatibility = await inspectCompatibility(bytes, request.fileName);
      let report;
      if (compatibility.ok) {
        ({ report } = await applySkezmodPatch(bytes, {
          dryRun: true,
          inputFileName: request.fileName,
          outputFileName: 'MANAGPRE.skezmod.exe',
        }));
      }

      const response: WorkerResponse = {
        id: request.id,
        type: 'inspect_result',
        compatibility,
        report,
      };
      ctx.postMessage(response);
      return;
    }

    const compatibility = await inspectCompatibility(bytes, request.fileName);
    if (!compatibility.ok) {
      const blocked: WorkerResponse = {
        id: request.id,
        type: 'error',
        error: compatibility.reasons.join(' '),
      };
      ctx.postMessage(blocked);
      return;
    }

    const { outputBytes, report } = await applySkezmodPatch(bytes, {
      dryRun: false,
      inputFileName: request.fileName,
      outputFileName: 'MANAGPRE.skezmod.exe',
    });

    const normalizedOutput = new Uint8Array(outputBytes);
    const transferable = normalizedOutput.buffer;

    const response: WorkerResponse = {
      id: request.id,
      type: 'apply_result',
      compatibility,
      report,
      outputBytes: transferable,
    };

    ctx.postMessage(response, [transferable]);
  } catch (error) {
    const message = error instanceof Error ? error.message : 'Unknown worker error';
    const response: WorkerResponse = {
      id: request.id,
      type: 'error',
      error: message,
    };
    ctx.postMessage(response);
  }
};

export {};
