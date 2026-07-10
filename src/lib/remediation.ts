import type { LogSourceId } from '../data/catalogue';
import { sourceMetadata, type RemediationRecord, type RemediationStatus } from '../data/source-metadata';

export type RemediationState = Record<LogSourceId, RemediationRecord>;

export interface RemediationStats {
  open: number;
  blocked: number;
  overdue: number;
  acceptedRisk: number;
  missingAccountability: number;
  missingValidationEvidence: number;
}

export function createInitialRemediationState(): RemediationState {
  return Object.fromEntries(
    Object.entries(sourceMetadata).map(([sourceId, metadata]) => [sourceId, { ...metadata.remediation }]),
  ) as RemediationState;
}

/** Merge imported state over catalogue defaults so older snapshots remain usable as fields evolve. */
export function normalizeRemediationState(value?: Partial<RemediationState>): RemediationState {
  const defaults = createInitialRemediationState();
  return Object.fromEntries(
    Object.entries(defaults).map(([sourceId, record]) => [
      sourceId,
      { ...record, ...(value?.[sourceId as LogSourceId] ?? {}) },
    ]),
  ) as RemediationState;
}

export function buildRemediationStats(
  state: RemediationState,
  activeSourceIds: LogSourceId[],
  today = new Date().toISOString().slice(0, 10),
): RemediationStats {
  const records = activeSourceIds.map((sourceId) => state[sourceId]).filter(Boolean);
  const closed: RemediationStatus[] = ['verified', 'accepted-risk'];

  return {
    open: records.filter((record) => !closed.includes(record.status)).length,
    blocked: records.filter((record) => record.status === 'blocked').length,
    overdue: records.filter(
      (record) => !closed.includes(record.status) && Boolean(record.targetDate) && record.targetDate < today,
    ).length,
    acceptedRisk: records.filter((record) => record.status === 'accepted-risk').length,
    missingAccountability: records.filter(
      (record) => !record.gapOwner.trim() || !record.businessOwner.trim() || !record.engineeringOwner.trim(),
    ).length,
    missingValidationEvidence: records.filter(
      (record) => record.status === 'verified' && (!record.validationMethod.trim() || !record.evidenceReference.trim()),
    ).length,
  };
}

export function remediationGovernanceWarnings(record: RemediationRecord): string[] {
  const warnings: string[] = [];
  if (!record.gapOwner.trim() || !record.businessOwner.trim() || !record.engineeringOwner.trim()) {
    warnings.push('Assign accountable, business, and engineering owners.');
  }
  if (record.status === 'verified' && !record.validationMethod.trim()) {
    warnings.push('A verified item needs a validation method.');
  }
  if (record.status === 'verified' && !record.evidenceReference.trim()) {
    warnings.push('A verified item needs an evidence reference.');
  }
  if (record.status === 'accepted-risk' && !record.acceptedRiskRationale.trim()) {
    warnings.push('Accepted risk needs a recorded rationale.');
  }
  if (record.status === 'accepted-risk' && !record.riskReviewDate) {
    warnings.push('Accepted risk needs a review date.');
  }
  return warnings;
}
