import type { LogSourceId } from '../data/catalogue';
import type { AssessmentMetadata, AssessmentMode, SourceAssessmentState } from './assessment';

export const snapshotStorageKey = 'gaps-analysis-tool.snapshots';

export interface AssessmentSnapshot {
  id: string;
  createdAt: string;
  catalogueVersion: string;
  mode: AssessmentMode;
  metadata: AssessmentMetadata;
  sourceState: Record<LogSourceId, SourceAssessmentState>;
}

export interface SnapshotComparison {
  scoreDelta: number;
  highRiskGapDelta: number;
  readySourceDelta: number;
  evidenceCheckDelta: number;
}

export interface ComparisonMetricsInput {
  overallScore: number;
  highRiskGapCount: number;
  readySourceCount: number;
  evidenceCheckCount: number;
}

export function createSnapshot(params: Omit<AssessmentSnapshot, 'id' | 'createdAt'>): AssessmentSnapshot {
  const stamp = new Date().toISOString();
  return {
    id: `${params.metadata.name || 'assessment'}-${stamp}`,
    createdAt: stamp,
    ...params,
  };
}

export function serializeSnapshot(snapshot: AssessmentSnapshot): string {
  return JSON.stringify(snapshot, null, 2);
}

export function parseSnapshot(json: string): AssessmentSnapshot {
  const parsed = JSON.parse(json) as AssessmentSnapshot;
  if (!parsed?.id || !parsed?.catalogueVersion || !parsed?.sourceState) {
    throw new Error('Invalid snapshot file');
  }
  return parsed;
}

export function loadSnapshots(storage: Pick<Storage, 'getItem'>): AssessmentSnapshot[] {
  const raw = storage.getItem(snapshotStorageKey);
  if (!raw) return [];

  try {
    const parsed = JSON.parse(raw) as AssessmentSnapshot[];
    return Array.isArray(parsed) ? parsed : [];
  } catch {
    return [];
  }
}

export function saveSnapshot(storage: Pick<Storage, 'getItem' | 'setItem'>, snapshot: AssessmentSnapshot): AssessmentSnapshot[] {
  const current = loadSnapshots(storage);
  const next = [snapshot, ...current.filter((item) => item.id !== snapshot.id)].slice(0, 12);
  storage.setItem(snapshotStorageKey, JSON.stringify(next));
  return next;
}

export function buildSnapshotComparison(
  current: ComparisonMetricsInput,
  baseline: ComparisonMetricsInput,
): SnapshotComparison {
  return {
    scoreDelta: round2(current.overallScore - baseline.overallScore),
    highRiskGapDelta: current.highRiskGapCount - baseline.highRiskGapCount,
    readySourceDelta: current.readySourceCount - baseline.readySourceCount,
    evidenceCheckDelta: current.evidenceCheckCount - baseline.evidenceCheckCount,
  };
}

function round2(value: number): number {
  return Math.round(value * 100) / 100;
}
