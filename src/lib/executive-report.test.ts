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

  it('includes methodology, governance, and accepted-risk panels', () => {
    const sourceState = createInitialAssessmentState('demo');
    const verification = buildVerificationSummary(catalogue.logSources, sourceState);
    const readiness = buildSourceReadinessMap(verification);
    const summary = buildCoverageSummary(catalogue.riskVectors, readiness);

    const report = buildExecutiveReport({
      mode: 'demo',
      metadata: {
        name: 'Governance check',
        owner: 'SOC',
        notes: '',
        scope: 'Readiness',
      },
      summary,
      verificationSummary: verification,
      scenarios: catalogue.threatScenarios,
      sources: catalogue.logSources,
      sourceMetadata,
      remediationState: {
        ...Object.fromEntries(
          catalogue.logSources.map((source) => [source.id, { ...sourceMetadata[source.id].remediation }]),
        ),
        email: {
          ...sourceMetadata.email.remediation,
          status: 'accepted-risk',
          acceptedRiskRationale: 'Mailbox content out of scope for this assessment wave.',
          riskReviewDate: '2026-12-01',
          gapOwner: 'Messaging security',
          businessOwner: 'Collaboration owner',
          engineeringOwner: 'Messaging security',
        },
      } as never,
    });

    // Force accepted-risk on verification path via maturity if demo did not.
    const acceptedViaMaturity = createInitialAssessmentState('real');
    acceptedViaMaturity.email = {
      maturity: 'accepted-risk',
      verifiedCheckIds: [],
    };
    const verificationAccepted = buildVerificationSummary(catalogue.logSources, acceptedViaMaturity);
    const reportAccepted = buildExecutiveReport({
      mode: 'real',
      metadata: {
        name: 'Accepted risk review',
        owner: 'SOC',
        notes: '',
        scope: 'Readiness',
      },
      summary: buildCoverageSummary(catalogue.riskVectors, buildSourceReadinessMap(verificationAccepted)),
      verificationSummary: verificationAccepted,
      scenarios: catalogue.threatScenarios,
      sources: catalogue.logSources,
      sourceMetadata,
      remediationState: {
        ...Object.fromEntries(
          catalogue.logSources.map((source) => [source.id, { ...sourceMetadata[source.id].remediation }]),
        ),
        email: {
          ...sourceMetadata.email.remediation,
          status: 'accepted-risk',
          acceptedRiskRationale: 'Mailbox content out of scope for this assessment wave.',
          riskReviewDate: '2026-12-01',
          gapOwner: 'Messaging security',
          businessOwner: 'Collaboration owner',
          engineeringOwner: 'Messaging security',
        },
      } as never,
    });

    expect(report.methodology.join(' ')).toMatch(/Investigation-ready/i);
    expect(report.methodology.join(' ')).toMatch(/not that a control blocked/i);
    expect(report.methodology.join(' ')).toMatch(/GREEN ≥ 80%/i);
    expect(report.governance.join(' ')).toMatch(/Purpose limitation/i);
    expect(report.governance.join(' ')).toMatch(/No intent inference/i);
    expect(report.markdown).toContain('## Methodology');
    expect(report.markdown).toContain('## Governance');
    expect(report.markdown).toContain('## Accepted-risk detail');
    expect(report.markdown).toMatch(/Evidence readiness is not prevention/i);

    expect(reportAccepted.acceptedRiskDetails.length).toBeGreaterThan(0);
    expect(reportAccepted.acceptedRiskDetails[0].rationale).toMatch(/Mailbox content out of scope/i);
    expect(reportAccepted.acceptedRiskDetails[0].reviewDate).toBe('2026-12-01');
    expect(reportAccepted.markdown).toMatch(/Mailbox content out of scope/i);
  });
});
