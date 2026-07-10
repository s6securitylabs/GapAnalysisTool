import type { ThreatScenario, LogSource, LogSourceId } from '../data/catalogue';
import type { SourceMetadata } from '../data/source-metadata';
import type { RemediationState } from './remediation';
import { getScenarioStatus, type AssessmentMetadata, type AssessmentMode, type SourceVerificationSummary } from './assessment';
import { formatPercent, type CoverageSummary } from './coverage';

export interface ExecutiveReport {
  rag: 'green' | 'amber' | 'red';
  plainEnglishSummary: string;
  strengths: string[];
  weaknesses: string[];
  topGaps: string[];
  recommendedInvestments: string[];
  scenarioSummary: string[];
  markdown: string;
}

export function buildExecutiveReport(params: {
  mode: AssessmentMode;
  metadata: AssessmentMetadata;
  summary: CoverageSummary;
  verificationSummary: Map<LogSourceId, SourceVerificationSummary>;
  scenarios: ThreatScenario[];
  sources: LogSource[];
  sourceMetadata: Record<LogSourceId, SourceMetadata>;
  remediationState?: RemediationState;
  catalogueVersion?: string;
  generatedAt?: string;
}): ExecutiveReport {
  const { mode, metadata, summary, verificationSummary, scenarios, sources, sourceMetadata } = params;
  const remediationFor = (sourceId: LogSourceId) => params.remediationState?.[sourceId] ?? sourceMetadata[sourceId].remediation;
  const readySources = sources.filter((source) => verificationSummary.get(source.id)?.effective);
  const partialSources = sources.filter((source) => {
    const item = verificationSummary.get(source.id);
    return item && !item.effective && item.readinessScore > 0;
  });
  const acceptedRiskSources = sources.filter((source) => verificationSummary.get(source.id)?.acceptedRisk);
  const topGaps = summary.vectors
    .filter((item) => item.score < 0.8)
    .sort((a, b) => b.riskGapScore - a.riskGapScore)
    .slice(0, 5)
    .map((item) => `${item.vector.name}: ${item.vector.severity} risk, ${formatPercent(item.score)} evidence readiness, priority index ${item.riskGapScore.toFixed(1)}.`);
  const weakestVectors = summary.vectors
    .filter((item) => item.score < 0.8)
    .sort((a, b) => b.riskGapScore - a.riskGapScore)
    .slice(0, 3)
    .map((item) => `${item.vector.name} (${item.vector.severity}, ${formatPercent(item.score)} coverage)`);
  const bestDomains = summary.domains
    .filter((item) => item.score >= 0.8)
    .sort((a, b) => b.score - a.score)
    .slice(0, 2)
    .map((item) => `${item.domain} (${formatPercent(item.score)})`);
  const rag = summary.overallScore >= 0.8 ? 'green' : summary.overallScore >= 0.55 ? 'amber' : 'red';
  const strengths = [
    readySources.length > 0
      ? `${readySources.length} sources meet investigation-ready gating (all critical checks verified), including ${readySources.slice(0, 3).map((source) => source.name).join(', ')}.`
      : 'No source currently meets investigation-ready gating.',
    bestDomains.length > 0 ? `Strongest domains: ${bestDomains.join(' and ')}.` : 'No domain is yet at a strong readiness level.',
    `Coverage is based on verified evidence and maturity, not raw tool ownership.`,
  ];
  const weaknesses = [
    weakestVectors.length > 0 ? `Biggest exposed scenarios: ${weakestVectors.join('; ')}.` : 'No material vector gaps remain.',
    partialSources.length > 0
      ? `${partialSources.length} sources are only partially usable because fields, searchability, normalization, or verification are incomplete.`
      : 'There are no partially mature sources left in the middle state.',
    acceptedRiskSources.length > 0
      ? `${acceptedRiskSources.length} sources are flagged accepted-risk / not-applicable: they contribute no evidence and do not count toward readiness. Confirm each decision is justified and reviewable.`
      : 'No sources are flagged as accepted-risk.',
    mode === 'real'
      ? 'Real assessment mode is active, so no shortcut evidence seeding is allowed.'
      : 'Demo mode is active, so seeded evidence should not be mistaken for a production assessment.',
  ];
  const recommendedInvestments = summary.topMissingSources.slice(0, 4).map((item) => {
    const plan = remediationFor(item.sourceId);
    const source = sources.find((entry) => entry.id === item.sourceId);
    return `${source?.name ?? item.sourceId}: ${plan.recommendation} Owner: ${plan.gapOwner}.`;
  });
  const scenarioSummary = scenarios.map((scenario) => {
    const scenarioStatus = getScenarioStatus(scenario, verificationSummary);
    return `${scenario.title}: ${scenarioStatus.label} (${formatPercent(scenarioStatus.readinessScore)} readiness, ${scenarioStatus.criticalEffective}/${scenario.criticalSources.length} critical evidence sources ready).`;
  });
  const plainEnglishSummary = `Overall readiness is ${rag.toUpperCase()} at ${formatPercent(summary.overallScore)}. ${summary.highRiskGapCount} high or critical gaps remain. ${readySources.length} sources currently satisfy investigation-ready gating (all critical checks verified).`;

  const markdown = [
    `# Gaps Analysis Tool Report Summary`,
    ``,
    `- Assessment: ${metadata.name || 'Unnamed assessment'}`,
    `- Owner: ${metadata.owner || 'Unassigned'}`,
    `- Mode: ${mode === 'demo' ? 'Demo mode (seeded sample data)' : 'Real assessment mode'}`,
    `- Scope: ${metadata.scope || 'Not stated'}`,
    `- Catalogue version: ${params.catalogueVersion ?? 'unspecified'}`,
    `- Generated: ${params.generatedAt ?? new Date().toISOString()}`,
    `- Overall readiness: ${formatPercent(summary.overallScore)} (${rag.toUpperCase()})`,
    `- RAG legend: GREEN ≥ 80%, AMBER 55–79%, RED < 55% of severity-weighted evidence readiness`,
    `- High/critical gaps: ${summary.highRiskGapCount}`,
    `- Sources flagged accepted-risk (no evidence, excluded from readiness): ${acceptedRiskSources.length}`,
    ``,
    `## Plain-English Summary`,
    plainEnglishSummary,
    ``,
    `## Strengths`,
    ...strengths.map((item) => `- ${item}`),
    ``,
    `## Weaknesses`,
    ...weaknesses.map((item) => `- ${item}`),
    ``,
    `## Top Gaps`,
    ...topGaps.map((item) => `- ${item}`),
    ``,
    `## Recommended Investments`,
    ...recommendedInvestments.map((item) => `- ${item}`),
    ``,
    `## Remediation Governance`,
    ...summary.topMissingSources.slice(0, 5).map((item) => {
      const plan = remediationFor(item.sourceId);
      const source = sources.find((entry) => entry.id === item.sourceId);
      return `- ${source?.name ?? item.sourceId}: ${plan.status}; priority ${plan.priority}; SLA ${plan.slaDays} days; business owner ${plan.businessOwner}; detection/use case ${plan.detectionUseCase}; validation ${plan.validationMethod}; evidence ${plan.evidenceReference || 'not yet recorded'}.`;
    }),
    ``,
    `## Scenario Snapshot`,
    ...scenarioSummary.map((item) => `- ${item}`),
    ``,
    `## Guardrails`,
    `- This product does not ingest raw logs; it visualizes readiness based on verified evidence from other systems.`,
    `- HR, physical, email, and behavioral context require minimum-necessary access, counsel-approved purpose limitation, and corroboration.`,
  ].join('\n');

  return {
    rag,
    plainEnglishSummary,
    strengths,
    weaknesses,
    topGaps,
    recommendedInvestments,
    scenarioSummary,
    markdown,
  };
}
