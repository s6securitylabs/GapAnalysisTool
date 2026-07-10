import { catalogue, type ThreatScenario, type LogSource, type LogSourceId } from '../data/catalogue';
import type { CoverageSummary } from './coverage';

export type AssessmentMode = 'demo' | 'real';
export type VerificationMaturity =
  | 'not-collected'
  | 'collected-not-searchable'
  | 'searchable-missing-fields'
  | 'normalized-correlatable'
  | 'investigation-ready'
  | 'accepted-risk';

export interface SourceAssessmentState {
  maturity: VerificationMaturity;
  verifiedCheckIds: string[];
  evidenceReference?: string;
  validatedBy?: string;
  validatedAt?: string;
}

export interface AssessmentMetadata {
  name: string;
  owner: string;
  notes: string;
  scope: string;
}

export interface SourceVerificationSummary {
  sourceId: LogSourceId;
  maturity: VerificationMaturity;
  readinessScore: number;
  verifiedCheckIds: string[];
  verifiedChecks: number;
  totalChecks: number;
  criticalVerified: number;
  criticalTotal: number;
  effective: boolean;
  acceptedRisk: boolean;
  evidenceRecorded: boolean;
}

export interface VerificationStats {
  investigationReadySources: number;
  acceptedRiskSources: number;
  partialSources: number;
  blindSources: number;
  unverifiedCriticalChecks: number;
}

export interface VerificationDebtItem {
  sourceId: LogSourceId;
  sourceName: string;
  checkId: string;
  checkLabel: string;
  priority: 'critical' | 'recommended';
  verificationQuestion: string;
  impactedVectors: string[];
  impactCount: number;
}

export type ScenarioStatus = 'blind' | 'partial' | 'substantial' | 'investigation-ready';

export interface ScenarioAssessment {
  status: ScenarioStatus;
  label: string;
  icon: string;
  criticalEffective: number;
  criticalReady: number;
  recommendedReady: number;
  readinessScore: number;
}

export const defaultDemoSourceIds: LogSourceId[] = ['idp-auth', 'endpoint-edr', 'saas-audit', 'hr-case', 'siem-enrichment'];

export const maturityLabels: Record<VerificationMaturity, string> = {
  'not-collected': 'Not collected',
  'collected-not-searchable': 'Collected, not searchable',
  'searchable-missing-fields': 'Searchable, missing fields',
  'normalized-correlatable': 'Normalized / correlatable',
  'investigation-ready': 'Investigation-ready',
  'accepted-risk': 'Accepted risk / not applicable',
};

export const maturityWeights: Record<VerificationMaturity, number> = {
  'not-collected': 0,
  'collected-not-searchable': 0.2,
  'searchable-missing-fields': 0.45,
  'normalized-correlatable': 0.72,
  'investigation-ready': 1,
  'accepted-risk': 1,
};

export function createInitialAssessmentState(mode: AssessmentMode): Record<LogSourceId, SourceAssessmentState> {
  return Object.fromEntries(
    catalogue.logSources.map((source) => {
      const demoReady = mode === 'demo' && defaultDemoSourceIds.includes(source.id);
      return [
        source.id,
        {
          maturity: demoReady ? 'investigation-ready' : 'not-collected',
          verifiedCheckIds: demoReady
            ? source.verificationChecks.filter((check) => check.priority === 'critical').map((check) => check.id)
            : [],
          evidenceReference: demoReady ? 'Synthetic walkthrough evidence' : '',
          validatedBy: demoReady ? 'Demo seed' : '',
          validatedAt: demoReady ? '2026-01-01' : '',
        },
      ];
    }),
  ) as Record<LogSourceId, SourceAssessmentState>;
}

export function buildVerificationSummary(
  sources: LogSource[],
  sourceState: Record<LogSourceId, SourceAssessmentState>,
): Map<LogSourceId, SourceVerificationSummary> {
  return new Map(
    sources.map((source) => {
      // Guard against snapshots taken under an older catalogue that predates a source id.
      const state = sourceState[source.id] ?? { maturity: 'not-collected' as VerificationMaturity, verifiedCheckIds: [] };
      const criticalChecks = source.verificationChecks.filter((check) => check.priority === 'critical');
      const criticalVerified = criticalChecks.filter((check) => state.verifiedCheckIds.includes(check.id)).length;
      const verifiedChecks = source.verificationChecks.filter((check) => state.verifiedCheckIds.includes(check.id)).length;
      const criticalRatio = criticalChecks.length === 0 ? 1 : criticalVerified / criticalChecks.length;
      const acceptedRisk = state.maturity === 'accepted-risk';
      // Accepting risk on a source is an explicit decision NOT to hold evidence. It must never
      // inflate coverage/readiness (PRD §13: accepted_risk = 0 for coverage, flagged separately).
      const evidenceRecorded = Boolean(state.evidenceReference?.trim() && state.validatedBy?.trim() && state.validatedAt);
      // Keep unsupported "ready" claims below the 0.8 covered threshold. Critical checks
      // without a durable provenance record are useful partial evidence, not closure.
      const provenanceWeight = state.maturity === 'investigation-ready' && !evidenceRecorded ? 0.75 : 1;
      const readinessScore = acceptedRisk
        ? 0
        : round2(maturityWeights[state.maturity] * (criticalChecks.length === 0 ? 1 : 0.4 + criticalRatio * 0.6) * provenanceWeight);
      const effective = !acceptedRisk && state.maturity === 'investigation-ready' && criticalRatio === 1 && evidenceRecorded;

      return [
        source.id,
        {
          sourceId: source.id,
          maturity: state.maturity,
          readinessScore,
          verifiedCheckIds: [...state.verifiedCheckIds],
          verifiedChecks,
          totalChecks: source.verificationChecks.length,
          criticalVerified,
          criticalTotal: criticalChecks.length,
          effective,
          acceptedRisk,
          evidenceRecorded,
        },
      ];
    }),
  );
}

export function buildSourceReadinessMap(
  verificationSummary: Map<LogSourceId, SourceVerificationSummary>,
): Map<LogSourceId, number> {
  return new Map([...verificationSummary.entries()].map(([sourceId, summary]) => [sourceId, summary.readinessScore]));
}

export function buildVerificationStats(
  verificationSummary: Map<LogSourceId, SourceVerificationSummary>,
): VerificationStats {
  const values = [...verificationSummary.values()];
  return {
    investigationReadySources: values.filter((summary) => summary.effective && !summary.acceptedRisk).length,
    acceptedRiskSources: values.filter((summary) => summary.acceptedRisk).length,
    partialSources: values.filter((summary) => !summary.effective && summary.readinessScore > 0).length,
    blindSources: values.filter((summary) => summary.readinessScore === 0).length,
    unverifiedCriticalChecks: values.reduce((sum, summary) => sum + Math.max(summary.criticalTotal - summary.criticalVerified, 0), 0),
  };
}

export function buildVerificationDebt(
  sources: LogSource[],
  summary: CoverageSummary,
  verificationSummary: Map<LogSourceId, SourceVerificationSummary>,
): VerificationDebtItem[] {
  const sourceImpact = new Map(summary.topMissingSources.map((item) => [item.sourceId, item]));
  const vectorNamesBySource = new Map<LogSourceId, string[]>();

  for (const vector of summary.vectors) {
    for (const sourceId of vector.missingSources) {
      vectorNamesBySource.set(sourceId, [...(vectorNamesBySource.get(sourceId) ?? []), vector.vector.name]);
    }
  }

  return sources
    .flatMap((source) => {
      const state = verificationSummary.get(source.id);
      if (!state || state.acceptedRisk) return [];
      return source.verificationChecks
        .filter((check) => check.priority !== 'optional' && !state.verifiedCheckIds.includes(check.id))
        .map((check) => ({
          sourceId: source.id,
          sourceName: source.name,
          checkId: check.id,
          checkLabel: check.label,
          priority: check.priority as 'critical' | 'recommended',
          verificationQuestion: check.verificationQuestion,
          impactedVectors: [...new Set(vectorNamesBySource.get(source.id) ?? [])],
          impactCount: sourceImpact.get(source.id)?.count ?? 0,
        }));
    })
    .sort((a, b) => {
      const priorityDelta = (a.priority === 'critical' ? 0 : 1) - (b.priority === 'critical' ? 0 : 1);
      return priorityDelta || b.impactCount - a.impactCount || a.sourceName.localeCompare(b.sourceName);
    });
}

export function getScenarioStatus(
  scenario: ThreatScenario,
  verificationSummary: Map<LogSourceId, SourceVerificationSummary>,
): ScenarioAssessment {
  const criticalSummaries = scenario.criticalSources.map((sourceId) => verificationSummary.get(sourceId));
  const recommendedSummaries = scenario.recommendedSources.map((sourceId) => verificationSummary.get(sourceId));
  const criticalEffective = criticalSummaries.filter((summary) => summary?.effective).length;
  const criticalReady = criticalSummaries.filter((summary) => (summary?.readinessScore ?? 0) > 0).length;
  const recommendedReady = recommendedSummaries.filter((summary) => (summary?.readinessScore ?? 0) > 0).length;
  const criticalAverage = average(criticalSummaries.map((summary) => summary?.readinessScore ?? 0));
  const recommendedAverage = average(recommendedSummaries.map((summary) => summary?.readinessScore ?? 0));
  const readinessScore = round2(criticalAverage * 0.85 + recommendedAverage * 0.15);

  if (criticalEffective === scenario.criticalSources.length) {
    return {
      status: 'investigation-ready',
      label: 'Investigation-ready',
      icon: 'OK',
      criticalEffective,
      criticalReady,
      recommendedReady,
      readinessScore,
    };
  }

  if (criticalReady === 0 && recommendedReady === 0) {
    return {
      status: 'blind',
      label: 'Blind',
      icon: '!!',
      criticalEffective,
      criticalReady,
      recommendedReady,
      readinessScore,
    };
  }

  if (criticalReady === scenario.criticalSources.length || readinessScore >= 0.65) {
    return {
      status: 'substantial',
      label: 'Substantial but incomplete',
      icon: '>>',
      criticalEffective,
      criticalReady,
      recommendedReady,
      readinessScore,
    };
  }

  return {
    status: 'partial',
    label: 'Partial evidence',
    icon: '!>',
    criticalEffective,
    criticalReady,
    recommendedReady,
    readinessScore,
  };
}

function round2(value: number): number {
  return Math.round(value * 100) / 100;
}

function average(values: number[]): number {
  if (values.length === 0) return 0;
  return values.reduce((sum, value) => sum + value, 0) / values.length;
}
