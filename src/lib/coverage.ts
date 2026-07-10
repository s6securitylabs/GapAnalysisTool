import type { EvidenceMapping, LogSource, LogSourceId, RiskVector, Severity } from '../data/catalogue';
import type { SourceMetadata } from '../data/source-metadata';

export interface QuestionCoverage {
  questionId: string;
  question: string;
  score: number;
  status: CoverageStatus;
  coveredSources: EvidenceMapping[];
  missingPrimarySources: EvidenceMapping[];
  missingSupportingSources: EvidenceMapping[];
}

export interface VectorCoverage {
  vector: RiskVector;
  score: number;
  status: CoverageStatus;
  severityWeight: number;
  riskGapScore: number;
  questions: QuestionCoverage[];
  availableSources: LogSourceId[];
  missingSources: LogSourceId[];
}

export interface DomainCoverage {
  domain: string;
  score: number;
  riskGapScore: number;
  vectors: VectorCoverage[];
}

export interface CoverageSummary {
  overallScore: number;
  totalVectors: number;
  highRiskGapCount: number;
  selectedSourceCount: number;
  selectedSources: LogSourceId[];
  domains: DomainCoverage[];
  vectors: VectorCoverage[];
  topMissingSources: Array<{ sourceId: LogSourceId; count: number; weightedGap: number }>;
}

export type CoverageStatus = 'covered' | 'partial' | 'gap';
export type SourceReadinessInput = Iterable<LogSourceId> | ReadonlyMap<LogSourceId, number>;

export const severityWeights: Record<Severity, number> = {
  critical: 5,
  high: 4,
  medium: 3,
  low: 2,
};

const sourceStrengthWeights: Record<EvidenceMapping['strength'], number> = {
  primary: 1,
  supporting: 0.65,
  context: 0.35,
};

export function scoreQuestion(evidence: EvidenceMapping[], sourceReadiness: SourceReadinessInput): number {
  if (evidence.length === 0) return 0;

  const readiness = normalizeSourceReadiness(sourceReadiness);
  const primaryEvidence = evidence.filter((item) => item.strength === 'primary');
  const evidenceToScore = primaryEvidence.length > 0 ? primaryEvidence : evidence;
  const denominator = evidenceToScore.reduce((sum, item) => sum + sourceStrengthWeights[item.strength], 0);
  const numerator = evidenceToScore.reduce(
    (sum, item) => sum + sourceStrengthWeights[item.strength] * (readiness.get(item.sourceId) ?? 0),
    0,
  );

  const directScore = denominator === 0 ? 0 : numerator / denominator;
  const supportingBoost = evidence
    .filter((item) => item.strength !== 'primary')
    .reduce((sum, item) => sum + sourceStrengthWeights[item.strength] * 0.15 * (readiness.get(item.sourceId) ?? 0), 0);

  return clamp(directScore + supportingBoost, 0, 1);
}

export function statusForScore(score: number): CoverageStatus {
  if (score >= 0.8) return 'covered';
  if (score > 0) return 'partial';
  return 'gap';
}

export function scoreVector(vector: RiskVector, sourceReadiness: SourceReadinessInput): VectorCoverage {
  const readiness = normalizeSourceReadiness(sourceReadiness);
  const availableSourceIds = [...readiness.entries()].filter(([, score]) => score > 0).map(([sourceId]) => sourceId);
  const availableSources = new Set(availableSourceIds);
  const questions = vector.investigationQuestions.map((question) => {
    const score = scoreQuestion(question.evidence, readiness);
    return {
      questionId: question.id,
      question: question.question,
      score,
      status: statusForScore(score),
      coveredSources: question.evidence.filter((item) => availableSources.has(item.sourceId)),
      missingPrimarySources: question.evidence.filter((item) => item.strength === 'primary' && !availableSources.has(item.sourceId)),
      missingSupportingSources: question.evidence.filter((item) => item.strength !== 'primary' && !availableSources.has(item.sourceId)),
    };
  });
  const score = questions.length === 0 ? 0 : average(questions.map((question) => question.score));
  const severityWeight = severityWeights[vector.severity];
  const missingSources = unique(
    vector.investigationQuestions.flatMap((question) =>
      question.evidence.filter((item) => !availableSources.has(item.sourceId)).map((item) => item.sourceId),
    ),
  );

  return {
    vector,
    score,
    status: statusForScore(score),
    severityWeight,
    riskGapScore: (1 - score) * severityWeight,
    questions,
    availableSources: unique(
      vector.investigationQuestions.flatMap((question) =>
        question.evidence.filter((item) => availableSources.has(item.sourceId)).map((item) => item.sourceId),
      ),
    ),
    missingSources,
  };
}

export function buildCoverageSummary(vectors: RiskVector[], sourceReadiness: SourceReadinessInput): CoverageSummary {
  const readiness = normalizeSourceReadiness(sourceReadiness);
  const selectedSourceList = unique([...readiness.entries()].filter(([, score]) => score > 0).map(([sourceId]) => sourceId));
  const scoredVectors = vectors.map((vector) => scoreVector(vector, readiness));
  const domains = unique(vectors.map((vector) => vector.domain)).map((domain) => {
    const domainVectors = scoredVectors.filter((item) => item.vector.domain === domain);
    const denominator = domainVectors.reduce((sum, item) => sum + item.severityWeight, 0);
    const score = denominator === 0 ? 0 : domainVectors.reduce((sum, item) => sum + item.score * item.severityWeight, 0) / denominator;
    return {
      domain,
      score,
      riskGapScore: domainVectors.reduce((sum, item) => sum + item.riskGapScore, 0),
      vectors: domainVectors,
    };
  });
  const totalWeight = scoredVectors.reduce((sum, item) => sum + item.severityWeight, 0);
  const overallScore = totalWeight === 0 ? 0 : scoredVectors.reduce((sum, item) => sum + item.score * item.severityWeight, 0) / totalWeight;

  const missing = new Map<LogSourceId, { count: number; weightedGap: number }>();
  for (const vector of scoredVectors) {
    for (const sourceId of vector.missingSources) {
      const item = missing.get(sourceId) ?? { count: 0, weightedGap: 0 };
      item.count += 1;
      item.weightedGap += vector.riskGapScore;
      missing.set(sourceId, item);
    }
  }

  return {
    overallScore,
    totalVectors: vectors.length,
    highRiskGapCount: scoredVectors.filter((item) => ['critical', 'high'].includes(item.vector.severity) && item.score < 0.8).length,
    selectedSourceCount: selectedSourceList.length,
    selectedSources: selectedSourceList,
    domains,
    vectors: scoredVectors,
    topMissingSources: [...missing.entries()]
      .map(([sourceId, value]) => ({ sourceId, ...value }))
      .sort((a, b) => b.weightedGap - a.weightedGap || b.count - a.count),
  };
}

export function formatPercent(score: number): string {
  return `${Math.round(score * 100)}%`;
}

export interface GapsCsvOptions {
  assessmentMode?: string;
  assessmentName?: string;
  assessmentOwner?: string;
  catalogueVersion?: string;
  generatedAt?: string;
  caveat?: string;
  sourceMetadata?: Record<LogSourceId, SourceMetadata>;
}

export function buildGapsCsv(summary: CoverageSummary, sources: LogSource[], options: GapsCsvOptions = {}): string {
  const sourceById = new Map(sources.map((source) => [source.id, source]));
  const selectedSourceNames = summary.selectedSources.map((sourceId) => sourceById.get(sourceId)?.name ?? sourceId).join('; ');
  const generatedAt = options.generatedAt ?? new Date().toISOString();
  const caveat = options.caveat ?? 'Readiness visualization only. This app does not ingest raw logs. Verify searchability, retention, legal approval, and correlation quality in the source systems before formal use.';
  const rows = summary.vectors
    .filter((item) => item.score < 0.8)
    .sort((a, b) => b.riskGapScore - a.riskGapScore)
    .map((item) => {
      const missingSources = item.missingSources.map((sourceId) => sourceById.get(sourceId)?.name ?? sourceId);
      const priorityGapChecks = item.missingSources
        .flatMap((sourceId) => {
          const source = sourceById.get(sourceId);
          if (!source) return [];
          return source.verificationChecks
            .filter((check) => check.priority !== 'optional')
            .map((check) => `${check.priority}: ${source.name} - ${check.label}`);
        });
      const privacyNotes = item.missingSources.flatMap((sourceId) => options.sourceMetadata?.[sourceId]?.privacyNotes ?? []);
      const gapOwners = item.missingSources.map((sourceId) => options.sourceMetadata?.[sourceId]?.remediation.gapOwner ?? '').filter(Boolean);
      const businessOwners = item.missingSources.map((sourceId) => options.sourceMetadata?.[sourceId]?.remediation.businessOwner ?? '').filter(Boolean);
      const dueDates = item.missingSources.map((sourceId) => options.sourceMetadata?.[sourceId]?.remediation.targetDate ?? '').filter(Boolean);
      const remediationPlans = item.missingSources.map((sourceId) => options.sourceMetadata?.[sourceId]?.remediation.recommendation ?? '').filter(Boolean);
      const remediationStatuses = item.missingSources.map((sourceId) => options.sourceMetadata?.[sourceId]?.remediation.status ?? '').filter(Boolean);
      const criticalVerificationQuestions = item.missingSources
        .flatMap((sourceId) => sourceById.get(sourceId)?.verificationChecks ?? [])
        .filter((check) => check.priority === 'critical')
        .map((check) => check.verificationQuestion);
      const gapQuestions = item.questions
        .filter((question) => question.score < 0.8)
        .map((question) => question.question);
      const availableSources = item.availableSources.map((sourceId) => sourceById.get(sourceId)?.name ?? sourceId);

      return [
        options.assessmentMode ?? '',
        options.assessmentName ?? '',
        options.assessmentOwner ?? '',
        options.catalogueVersion ?? '',
        generatedAt,
        selectedSourceNames,
        caveat,
        item.vector.id,
        item.vector.domain,
        item.vector.severity,
        item.vector.name,
        formatPercent(item.score),
        item.riskGapScore.toFixed(2),
        item.status,
        availableSources.join('; '),
        missingSources.join('; '),
        gapOwners.join('; '),
        businessOwners.join('; '),
        dueDates.join('; '),
        remediationStatuses.join('; '),
        remediationPlans.join(' | '),
        priorityGapChecks.join(' | '),
        criticalVerificationQuestions.join(' | '),
        gapQuestions.join(' | '),
        [...new Set(privacyNotes)].join(' | '),
      ];
    });

  return [
    [
      'assessment_mode',
      'assessment_name',
      'assessment_owner',
      'catalogue_version',
      'generated_at',
      'selected_sources',
      'assessment_caveat',
      'vector_id',
      'domain',
      'severity',
      'vector',
      'coverage',
      'risk_gap_score',
      'status',
      'available_sources',
      'missing_sources',
      'gap_owners',
      'business_owners',
      'target_dates',
      'remediation_statuses',
      'remediation_recommendations',
      'priority_gap_checks',
      'critical_verification_questions',
      'gap_questions',
      'privacy_legal_notes',
    ],
    ...rows,
  ]
    .map((row) => row.map(escapeCsvCell).join(','))
    .join('\n');
}

function normalizeSourceReadiness(sourceReadiness: SourceReadinessInput): Map<LogSourceId, number> {
  if (sourceReadiness instanceof Map) {
    return new Map(sourceReadiness);
  }

  return new Map(([...sourceReadiness] as LogSourceId[]).map((sourceId) => [sourceId, 1] as const));
}

function escapeCsvCell(value: string): string {
  if (!/[",\n\r]/.test(value)) return value;
  return `"${value.replaceAll('"', '""')}"`;
}

function average(values: number[]): number {
  return values.length === 0 ? 0 : values.reduce((sum, value) => sum + value, 0) / values.length;
}

function clamp(value: number, min: number, max: number): number {
  return Math.max(min, Math.min(max, value));
}

function unique<T>(values: T[]): T[] {
  return [...new Set(values)];
}
