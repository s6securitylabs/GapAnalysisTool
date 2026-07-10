import { catalogue, type LogSourceId } from '../data/catalogue';
import type { AssessmentMetadata, AssessmentMode, SourceAssessmentState } from './assessment';
import { normalizeRemediationState, type RemediationState } from './remediation';

export const snapshotStorageKey = 'gaps-analysis-tool.snapshots';

/** Renamed verification check IDs across catalogue schema revisions. */
const CHECK_ID_MIGRATIONS: Record<string, string> = {
  'hr-status-dates': 'hr-lifecycle-dates',
  'hr-transition-controls': 'ig-transition-tasks',
};

/**
 * Maps known verification check IDs (after CHECK_ID_MIGRATIONS) onto the four
 * sources that replaced the legacy combined `hr-case` evidence source.
 */
const LEGACY_HR_CASE_CHECK_TARGETS: Record<string, LogSourceId> = {
  'hr-lifecycle-dates': 'workforce-lifecycle',
  'hr-role-context': 'workforce-lifecycle',
  'ig-access-recertification': 'identity-governance',
  'ig-transition-tasks': 'identity-governance',
  'ig-exception-approvals': 'identity-governance',
  'asset-assignment': 'asset-custody',
  'asset-return': 'asset-custody',
  'asset-custody-audit': 'asset-custody',
  'hr-case-context': 'case-management',
  'hr-referral-governance': 'case-management',
  'hr-access-controls': 'case-management',
};

const HR_CASE_SPLIT_TARGETS: LogSourceId[] = [
  'workforce-lifecycle',
  'identity-governance',
  'asset-custody',
  'case-management',
];

/** Critical checks introduced after earlier catalogue versions that require re-verification. */
const INTRODUCED_CRITICAL_CHECKS: Record<string, string[]> = {
  'workforce-lifecycle': ['hr-role-context'],
  'identity-governance': ['ig-access-recertification', 'ig-transition-tasks'],
  'asset-custody': ['asset-assignment', 'asset-return'],
  'case-management': ['hr-access-controls'],
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

function emptySourceState(partial?: Partial<SourceAssessmentState>): SourceAssessmentState {
  return {
    maturity: 'not-collected',
    verifiedCheckIds: [],
    evidenceReference: '',
    validatedBy: '',
    validatedAt: '',
    ...partial,
  };
}

function remapCheckIds(checkIds: string[] | undefined, sourceId: string, notes: string[]): string[] {
  const remapped: string[] = [];
  const verifiedCheckIds = [...new Set(
    (checkIds ?? []).map((checkId) => {
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

  return verifiedCheckIds;
}

function fanOutLegacyHrCase(
  sourceState: Record<string, SourceAssessmentState | undefined>,
  notes: string[],
): void {
  const legacy = sourceState['hr-case'];
  if (!legacy) return;

  const remappedChecks = remapCheckIds(legacy.verifiedCheckIds, 'hr-case', notes);
  const routed = new Map<LogSourceId, string[]>();
  const unrouted: string[] = [];

  for (const checkId of remappedChecks) {
    const target = LEGACY_HR_CASE_CHECK_TARGETS[checkId];
    if (!target) {
      unrouted.push(checkId);
      continue;
    }
    const list = routed.get(target) ?? [];
    list.push(checkId);
    routed.set(target, list);
  }

  for (const target of HR_CASE_SPLIT_TARGETS) {
    const existing = sourceState[target];
    const inheritedChecks = routed.get(target) ?? [];
    if (existing) {
      sourceState[target] = {
        ...existing,
        verifiedCheckIds: [...new Set([...(existing.verifiedCheckIds ?? []), ...inheritedChecks])],
      };
    } else {
      sourceState[target] = emptySourceState({
        maturity: legacy.maturity,
        verifiedCheckIds: inheritedChecks,
        evidenceReference: legacy.evidenceReference,
        validatedBy: legacy.validatedBy,
        validatedAt: legacy.validatedAt,
      });
    }
  }

  notes.push(
    'Source hr-case: split into workforce-lifecycle, identity-governance, asset-custody, and case-management; preserved verified check IDs where they still exist.',
  );
  if (unrouted.length > 0) {
    notes.push(
      `Source hr-case: dropped unknown verification checks no longer in the catalogue (${unrouted.join(', ')}).`,
    );
  }

  delete sourceState['hr-case'];
}

export function migrateSnapshot(snapshot: AssessmentSnapshot): AssessmentSnapshot {
  const notes: string[] = [...(snapshot.migrationNotes ?? [])];
  const knownCheckIds = new Set(
    catalogue.logSources.flatMap((source) => source.verificationChecks.map((check) => check.id)),
  );
  const knownSourceIds = new Set(catalogue.logSources.map((source) => source.id));

  const working: Record<string, SourceAssessmentState | undefined> = {
    ...(snapshot.sourceState ?? {}),
  };

  fanOutLegacyHrCase(working, notes);

  const sourceState = Object.fromEntries(
    Object.entries(working)
      .filter(([sourceId, state]) => Boolean(state) && (knownSourceIds.has(sourceId as LogSourceId) || sourceId === 'hr-case'))
      .map(([sourceId, state]) => {
        if (!state) return [sourceId, state];

        const verifiedCheckIds = remapCheckIds(state.verifiedCheckIds, sourceId, notes);

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
      })
      .filter(([sourceId]) => knownSourceIds.has(sourceId as LogSourceId)),
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
