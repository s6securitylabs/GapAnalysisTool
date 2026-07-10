import { catalogue, type LogSourceId } from '../data/catalogue';
import type { AssessmentMetadata, AssessmentMode, SourceAssessmentState } from './assessment';
import { normalizeRemediationState, type RemediationState } from './remediation';

export const snapshotStorageKey = 'gaps-analysis-tool.snapshots';

/** Renamed verification check IDs across catalogue schema revisions. */
const CHECK_ID_MIGRATIONS: Record<string, string> = {
  'hr-status-dates': 'hr-lifecycle-dates',
};

/** Critical checks introduced after earlier catalogue versions that require re-verification. */
const INTRODUCED_CRITICAL_CHECKS: Record<string, string[]> = {
  'hr-case': ['hr-transition-controls', 'hr-access-controls', 'hr-role-context'],
};

export interface AssessmentSnapshot {
  id: string;
  createdAt: string;
  catalogueVersion: string;
  mode: AssessmentMode;
  metadata: AssessmentMetadata;
  sourceState: Record<LogSourceId, SourceAssessmentState>;
  remediationState: RemediationState;
  /** Human-readable notes produced when older catalogue evidence was remapped. */
  migrationNotes?: string[];
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

export function createSnapshot(
  params: Omit<AssessmentSnapshot, 'id' | 'createdAt' | 'remediationState' | 'migrationNotes'> & {
    remediationState?: RemediationState;
    migrationNotes?: string[];
  },
): AssessmentSnapshot {
  const stamp = new Date().toISOString();
  return {
    id: `${params.metadata.name || 'assessment'}-${stamp}`,
    createdAt: stamp,
    ...params,
    remediationState: normalizeRemediationState(params.remediationState),
  };
}

export function serializeSnapshot(snapshot: AssessmentSnapshot): string {
  return JSON.stringify(snapshot, null, 2);
}

export function migrateSnapshot(snapshot: AssessmentSnapshot): AssessmentSnapshot {
  const notes: string[] = [...(snapshot.migrationNotes ?? [])];
  const knownCheckIds = new Set(
    catalogue.logSources.flatMap((source) => source.verificationChecks.map((check) => check.id)),
  );
  const sourceState = Object.fromEntries(
    Object.entries(snapshot.sourceState ?? {}).map(([sourceId, state]) => {
      if (!state) return [sourceId, state];

      const remapped: string[] = [];
      const verifiedCheckIds = [...new Set(
        (state.verifiedCheckIds ?? []).map((checkId) => {
          const nextId = CHECK_ID_MIGRATIONS[checkId] ?? checkId;
          if (nextId !== checkId) {
            remapped.push(`${checkId} → ${nextId}`);
          }
          return nextId;
        }),
      )];

      if (remapped.length > 0) {
        notes.push(
          `Source ${sourceId}: preserved verified workforce evidence by remapping ${remapped.join(', ')}.`,
        );
      }

      const unknown = verifiedCheckIds.filter((checkId) => !knownCheckIds.has(checkId));
      if (unknown.length > 0) {
        notes.push(
          `Source ${sourceId}: dropped unknown verification checks no longer in the catalogue (${unknown.join(', ')}).`,
        );
      }

      const introduced = INTRODUCED_CRITICAL_CHECKS[sourceId] ?? [];
      const missingIntroduced = introduced.filter((checkId) => !verifiedCheckIds.includes(checkId));
      if (missingIntroduced.length > 0 && state.maturity === 'investigation-ready') {
        notes.push(
          `Source ${sourceId}: catalogue added critical checks that still need verification (${missingIntroduced.join(', ')}). Investigation-ready status is no longer automatic.`,
        );
      }

      return [
        sourceId,
        {
          ...state,
          verifiedCheckIds: verifiedCheckIds.filter((checkId) => knownCheckIds.has(checkId)),
        },
      ];
    }),
  ) as Record<LogSourceId, SourceAssessmentState>;

  const uniqueNotes = [...new Set(notes)];
  return {
    ...snapshot,
    catalogueVersion: catalogue.version,
    sourceState,
    remediationState: normalizeRemediationState(snapshot.remediationState),
    migrationNotes: uniqueNotes.length > 0 ? uniqueNotes : undefined,
  };
}

export function parseSnapshot(json: string): AssessmentSnapshot {
  const parsed = JSON.parse(json) as AssessmentSnapshot;
  if (!parsed?.id || !parsed?.catalogueVersion || !parsed?.sourceState) {
    throw new Error('Invalid snapshot file');
  }
  return migrateSnapshot(parsed);
}

export function loadSnapshots(storage: Pick<Storage, 'getItem'>): AssessmentSnapshot[] {
  const raw = storage.getItem(snapshotStorageKey);
  if (!raw) return [];

  try {
    const parsed = JSON.parse(raw) as AssessmentSnapshot[];
    return Array.isArray(parsed) ? parsed.map((snapshot) => migrateSnapshot(snapshot)) : [];
  } catch {
    return [];
  }
}

export function saveSnapshot(storage: Pick<Storage, 'getItem' | 'setItem'>, snapshot: AssessmentSnapshot): AssessmentSnapshot[] {
  const current = loadSnapshots(storage);
  const migrated = migrateSnapshot(snapshot);
  const next = [migrated, ...current.filter((item) => item.id !== migrated.id)].slice(0, 12);
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
