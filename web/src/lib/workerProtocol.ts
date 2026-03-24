import type { CompatibilityResult, PatchReport } from './patchEngine';

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
    }
  | {
      id: number;
      type: 'error';
      error: string;
    };
