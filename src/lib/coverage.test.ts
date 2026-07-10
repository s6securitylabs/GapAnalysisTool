import { describe, expect, it } from 'vitest';
import { logSources, riskVectors } from '../data/catalogue';
import { sourceMetadata } from '../data/source-metadata';
import type { LogSourceId } from '../data/catalogue';
import { buildCoverageSummary, buildGapsCsv, scoreQuestion, scoreVector, statusForScore } from './coverage';

describe('coverage scoring', () => {
  it('scores a primary evidence question as covered when the primary source is investigation-ready', () => {
    const readiness = new Map<LogSourceId, number>([['saas-audit', 1]]);
    const score = scoreQuestion(
      [
        { sourceId: 'saas-audit', strength: 'primary', rationale: 'primary' },
        { sourceId: 'dlp', strength: 'supporting', rationale: 'supporting' },
      ],
      readiness,
    );

    expect(score).toBe(1);
    expect(statusForScore(score)).toBe('covered');
  });

  it('scores a missing primary with supporting evidence as partial but not covered', () => {
    const score = scoreQuestion(
      [
        { sourceId: 'saas-audit', strength: 'primary', rationale: 'primary' },
        { sourceId: 'dlp', strength: 'supporting', rationale: 'supporting' },
      ],
      new Map<LogSourceId, number>([['dlp', 0.45]]),
    );

    expect(score).toBeGreaterThan(0);
    expect(score).toBeLessThan(0.8);
    expect(statusForScore(score)).toBe('partial');
  });

  it('identifies vector gaps and missing sources from sparse readiness', () => {
    const vector = riskVectors.find((item) => item.id === 'access-retained-post-term');
    expect(vector).toBeDefined();

    const scored = scoreVector(vector!, new Map<LogSourceId, number>([['idp-auth', 1]]));

    expect(scored.status).toBe('partial');
    expect(scored.riskGapScore).toBeGreaterThan(0);
    expect(scored.missingSources).toContain('hr-case');
    expect(scored.availableSources).toContain('idp-auth');
  });

  it('builds an overall summary where every source at full readiness closes high-risk gaps', () => {
    const allSources = new Map(logSources.map((source) => [source.id, 1] as const));

    const summary = buildCoverageSummary(riskVectors, allSources);

    expect(summary.overallScore).toBe(1);
    expect(summary.highRiskGapCount).toBe(0);
    expect(summary.topMissingSources).toHaveLength(0);
  });

  it('prioritizes missing sources for a sparse environment', () => {
    const summary = buildCoverageSummary(riskVectors, new Map<LogSourceId, number>([['idp-auth', 1]]));

    expect(summary.overallScore).toBeLessThan(0.5);
    expect(summary.highRiskGapCount).toBeGreaterThan(0);
    expect(summary.topMissingSources[0].weightedGap).toBeGreaterThan(0);
  });

  it('exports prioritized gap rows with remediation and privacy columns', () => {
    const summary = buildCoverageSummary(riskVectors, new Map<LogSourceId, number>([['idp-auth', 1]]));
    const csv = buildGapsCsv(summary, logSources, {
      assessmentMode: 'real',
      assessmentName: 'Quarterly review',
      assessmentOwner: 'Security operations',
      catalogueVersion: 'test-version',
      generatedAt: '2026-07-08T00:00:00.000Z',
      sourceMetadata,
    });

    expect(csv.split('\n')[0]).toBe(
      'assessment_mode,assessment_name,assessment_owner,catalogue_version,generated_at,selected_sources,assessment_caveat,vector_id,domain,severity,vector,coverage,risk_gap_score,status,available_sources,missing_sources,gap_owners,business_owners,target_dates,remediation_statuses,remediation_recommendations,priority_gap_checks,critical_verification_questions,gap_questions,privacy_legal_notes',
    );
    expect(csv).toContain('Quarterly review');
    expect(csv).toContain('IdP authentication');
    expect(csv).toContain('HR / case management');
    expect(csv).toContain('purpose limitation');
    expect(csv).toContain('gap_owners');
    expect(csv).toContain('critical: HR / case management');
  });
});
