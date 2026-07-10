import { describe, expect, it } from 'vitest';
import { catalogue } from '../data/catalogue';
import {
  createSnapshot,
  parseSnapshot,
  saveSnapshot,
  serializeSnapshot,
  buildSnapshotComparison,
  migrateSnapshot,
} from './snapshots';

describe('snapshot helpers', () => {
  it('serializes and parses a snapshot', () => {
    const snapshot = createSnapshot({
      catalogueVersion: 'seed-0.1.0',
      mode: 'real',
      metadata: {
        name: 'Quarterly review',
        owner: 'Security operations',
        notes: '',
        scope: 'Readiness review',
      },
      sourceState: {
        'idp-auth': { maturity: 'investigation-ready', verifiedCheckIds: ['idp-login-logout'] },
      } as never,
    });

    const parsed = parseSnapshot(serializeSnapshot(snapshot));

    expect(parsed.id).toBe(snapshot.id);
    expect(parsed.metadata.name).toBe('Quarterly review');
    expect(parsed.mode).toBe('real');
    expect(parsed.remediationState['idp-auth'].engineeringOwner).toBe('Identity engineering');
  });

  it('upgrades an older snapshot with the current remediation schema', () => {
    const parsed = parseSnapshot(JSON.stringify({
      id: 'legacy',
      createdAt: '2026-01-01T00:00:00.000Z',
      catalogueVersion: 'seed-0.1.0',
      mode: 'real',
      metadata: { name: 'Legacy', owner: 'Ops', notes: '', scope: 'Review' },
      sourceState: {},
    }));

    expect(parsed.remediationState['siem-enrichment'].validationMethod).toContain('source canaries');
    expect(parsed.catalogueVersion).toBe(catalogue.version);
  });

  it('migrates v0.3 workforce check IDs without dropping verified evidence', () => {
    const migrated = migrateSnapshot({
      id: 'legacy-workforce',
      createdAt: '2026-01-01T00:00:00.000Z',
      catalogueVersion: 'seed-0.3.0',
      mode: 'real',
      metadata: { name: 'Workforce', owner: 'Ops', notes: '', scope: 'Review' },
      sourceState: {
        'hr-case': {
          maturity: 'investigation-ready',
          verifiedCheckIds: ['hr-status-dates', 'hr-role-context', 'legacy-unknown-check'],
          evidenceReference: 'Case file 12',
          validatedBy: 'Investigator',
          validatedAt: '2026-01-01',
        },
      } as never,
      remediationState: {} as never,
    });

    expect(migrated.sourceState['hr-case'].verifiedCheckIds).toEqual(
      expect.arrayContaining(['hr-lifecycle-dates', 'hr-role-context']),
    );
    expect(migrated.sourceState['hr-case'].verifiedCheckIds).not.toContain('hr-status-dates');
    expect(migrated.sourceState['hr-case'].verifiedCheckIds).not.toContain('legacy-unknown-check');
    expect(migrated.migrationNotes?.join(' ')).toMatch(/hr-status-dates → hr-lifecycle-dates/);
    expect(migrated.migrationNotes?.join(' ')).toMatch(/legacy-unknown-check/);
    expect(migrated.migrationNotes?.join(' ')).toMatch(/still need verification/);
    expect(migrated.catalogueVersion).toBe(catalogue.version);
  });

  it('stores the latest snapshot in local storage order', () => {
    const storage = new Map<string, string>();
    const fakeStorage = {
      getItem: (key: string) => storage.get(key) ?? null,
      setItem: (key: string, value: string) => {
        storage.set(key, value);
      },
    };

    const saved = saveSnapshot(
      fakeStorage,
      createSnapshot({
        catalogueVersion: 'seed-0.1.0',
        mode: 'demo',
        metadata: { name: 'A', owner: 'Ops', notes: '', scope: 'Demo' },
        sourceState: {} as never,
      }),
    );

    expect(saved).toHaveLength(1);
    expect(saved[0].metadata.name).toBe('A');
  });

  it('builds deltas for snapshot comparison', () => {
    const comparison = buildSnapshotComparison(
      { overallScore: 0.72, highRiskGapCount: 6, readySourceCount: 4, evidenceCheckCount: 10 },
      { overallScore: 0.5, highRiskGapCount: 9, readySourceCount: 2, evidenceCheckCount: 6 },
    );

    expect(comparison.scoreDelta).toBe(0.22);
    expect(comparison.highRiskGapDelta).toBe(-3);
    expect(comparison.readySourceDelta).toBe(2);
    expect(comparison.evidenceCheckDelta).toBe(4);
  });
});
