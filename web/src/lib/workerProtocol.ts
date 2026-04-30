import type { CompatibilityResult, PatchReport } from './patchEngine';
import type { StarsDatabaseRepairReport } from './starsDbRepair';

export type WorkerRequest =
  | {
      id: number;
      type: 'inspect';
      fileName: string;
      bytes: ArrayBuffer;
    }
  | {
      id: number;
      type: 'apply';
      fileName: string;
      bytes: ArrayBuffer;
      teamFileName?: string;
      teamBytes?: ArrayBuffer;
      playerFileName?: string;
      playerBytes?: ArrayBuffer;
    };

export type WorkerResponse =
  | {
      id: number;
      type: 'inspect_result';
      compatibility: CompatibilityResult;
      report?: PatchReport;
    }
  | {
      id: number;
      type: 'apply_result';
      compatibility: CompatibilityResult;
      report: PatchReport;
      outputBytes: ArrayBuffer;
      dbReport?: StarsDatabaseRepairReport;
      outputTeamBytes?: ArrayBuffer;
      outputPlayerBytes?: ArrayBuffer;
    }
  | {
      id: number;
      type: 'error';
      error: string;
    };
