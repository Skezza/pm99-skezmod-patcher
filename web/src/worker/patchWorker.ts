/// <reference lib="webworker" />

import { applySkezmodPatch, inspectCompatibility } from '../lib/patchEngine';
import { repairStarsDatabase } from '../lib/starsDbRepair';
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
    const transferables: Transferable[] = [transferable];

    let dbReport;
    let outputTeamBytes: ArrayBuffer | undefined;
    let outputPlayerBytes: ArrayBuffer | undefined;
    if (request.teamBytes && request.playerBytes && request.teamFileName && request.playerFileName) {
      const dbResult = await repairStarsDatabase(
        new Uint8Array(request.teamBytes),
        new Uint8Array(request.playerBytes),
        {
          dryRun: false,
          inputTeamFileName: request.teamFileName,
          inputPlayerFileName: request.playerFileName,
          outputTeamFileName: 'EQ98030.skezmod.FDI',
          outputPlayerFileName: 'JUG98030.skezmod.FDI',
        },
      );
      dbReport = dbResult.report;
      const normalizedTeam = new Uint8Array(dbResult.outputTeamBytes);
      const normalizedPlayer = new Uint8Array(dbResult.outputPlayerBytes);
      outputTeamBytes = normalizedTeam.buffer;
      outputPlayerBytes = normalizedPlayer.buffer;
      transferables.push(outputTeamBytes, outputPlayerBytes);
    }

    const response: WorkerResponse = {
      id: request.id,
      type: 'apply_result',
      compatibility,
      report,
      outputBytes: transferable,
      dbReport,
      outputTeamBytes,
      outputPlayerBytes,
    };

    ctx.postMessage(response, transferables);
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
