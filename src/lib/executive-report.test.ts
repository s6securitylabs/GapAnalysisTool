import { describe, expect, it } from 'vitest';
import { catalogue } from '../data/catalogue';
import { sourceMetadata } from '../data/source-metadata';
import { createInitialAssessmentState, buildVerificationSummary } from './assessment';
import { buildCoverageSummary } from './coverage';
import { buildSourceReadinessMap } from './assessment';
import { buildExecutiveReport } from './executive-report';

describe('executive report builder', () => {
  it('builds a plain-English summary and markdown export', () => {
    const sourceState = createInitialAssessmentState('demo');
    const verification = buildVerificationSummary(catalogue.logSources, sourceState);
    const readiness = buildSourceReadinessMap(verification);
    const summary = buildCoverageSummary(catalogue.riskVectors, readiness);

    const report = buildExecutiveReport({
      mode: 'demo',
      metadata: {
        name: 'Demo assessment',
        owner: 'SOC',
        notes: '',
        scope: 'Guided walkthrough',
      },
      summary,
      verificationSummary: verification,
      scenarios: catalogue.threatScenarios,
      sources: catalogue.logSources,
      sourceMetadata,
    });

    expect(report.plainEnglishSummary).toContain('Overall readiness');
    expect(report.strengths.length).toBeGreaterThan(0);
    expect(report.topGaps[0]).toMatch(/evidence readiness, priority index/i);
    expect(report.topGaps.join(' ')).not.toMatch(/accountable owner/i);
    expect(report.markdown).toContain('# Gaps Analysis Tool Report Summary');
    expect(report.markdown).toContain('Demo assessment');
    expect(report.scenarioSummary.join(' ')).toMatch(/critical evidence sources ready/i);
    expect(report.scenarioSummary.join(' ')).not.toMatch(/controls stopped|stopped \/ investigable/i);
  });
});
