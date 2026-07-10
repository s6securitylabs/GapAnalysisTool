import { describe, expect, it } from 'vitest';
import { buildRemediationStats, createBlankRemediationState, createInitialRemediationState, remediationGovernanceWarnings } from './remediation';

describe('remediation lifecycle', () => {
  it('starts real assessments without invented owners, dates, or agreed status', () => {
    const record = createBlankRemediationState()['idp-auth'];

    expect(record.gapOwner).toBe('');
    expect(record.businessOwner).toBe('');
    expect(record.engineeringOwner).toBe('');
    expect(record.targetDate).toBe('');
    expect(record.status).toBe('not-started');
    expect(record.recommendation).not.toBe('');
  });

  it('flags overdue and blocked active actions', () => {
    const state = createInitialRemediationState();
    state['proxy-dns'] = { ...state['proxy-dns'], status: 'blocked', targetDate: '2026-06-01' };

    const stats = buildRemediationStats(state, ['proxy-dns'], '2026-07-10');

    expect(stats.open).toBe(1);
    expect(stats.blocked).toBe(1);
    expect(stats.overdue).toBe(1);
  });

  it('requires validation evidence before a record can support verified closure', () => {
    const record = {
      ...createInitialRemediationState()['idp-auth'],
      status: 'verified' as const,
      validationMethod: '',
      evidenceReference: '',
    };

    expect(remediationGovernanceWarnings(record)).toEqual([
      'A verified item needs a validation method.',
      'A verified item needs an evidence reference.',
    ]);
  });

  it('requires accepted-risk rationale and a review date', () => {
    const record = {
      ...createInitialRemediationState()['idp-auth'],
      status: 'accepted-risk' as const,
      acceptedRiskRationale: '',
      riskReviewDate: '',
    };

    expect(remediationGovernanceWarnings(record)).toContain('Accepted risk needs a recorded rationale.');
    expect(remediationGovernanceWarnings(record)).toContain('Accepted risk needs a review date.');
  });
});
