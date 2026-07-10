import { describe, expect, it } from 'vitest';

import { catalogue } from '../data/catalogue';
import {
  buildVerificationSummary,
  createInitialAssessmentState,
  defaultDemoSourceIds,
  getScenarioStatus,
  type SourceAssessmentState,
} from './assessment';

const sources = catalogue.logSources;
const idp = sources.find((source) => source.id === 'idp-auth')!;
const idpCriticalIds = idp.verificationChecks.filter((check) => check.priority === 'critical').map((check) => check.id);
const evidenceRecord = { evidenceReference: 'TEST-1', validatedBy: 'Reviewer', validatedAt: '2026-07-10' };

function stateWith(overrides: Partial<Record<string, SourceAssessmentState>>) {
  const base = createInitialAssessmentState('real');
  return { ...base, ...overrides } as Record<string, SourceAssessmentState>;
}

describe('buildVerificationSummary gating', () => {
  it('marks a source investigation-ready only when every critical check is verified', () => {
    const summary = buildVerificationSummary(
      sources,
      stateWith({ 'idp-auth': { maturity: 'investigation-ready', verifiedCheckIds: idpCriticalIds, ...evidenceRecord } }),
    );
    const idpState = summary.get('idp-auth')!;
    expect(idpState.effective).toBe(true);
    expect(idpState.readinessScore).toBe(1);
  });

  it('does not close coverage when verification has no evidence provenance', () => {
    const summary = buildVerificationSummary(
      sources,
      stateWith({ 'idp-auth': { maturity: 'investigation-ready', verifiedCheckIds: idpCriticalIds } }),
    );

    expect(summary.get('idp-auth')!.effective).toBe(false);
    expect(summary.get('idp-auth')!.evidenceRecorded).toBe(false);
    expect(summary.get('idp-auth')!.readinessScore).toBeLessThan(0.8);
  });

  it('does not treat investigation-ready as effective when a critical check is missing', () => {
    const summary = buildVerificationSummary(
      sources,
      stateWith({ 'idp-auth': { maturity: 'investigation-ready', verifiedCheckIds: idpCriticalIds.slice(0, 1) } }),
    );
    const idpState = summary.get('idp-auth')!;
    expect(idpState.effective).toBe(false);
    expect(idpState.readinessScore).toBeLessThan(1);
    expect(idpState.readinessScore).toBeGreaterThan(0);
  });

  it('never lets accepted-risk inflate readiness or count as coverage (PRD §13)', () => {
    const summary = buildVerificationSummary(
      sources,
      stateWith({ 'idp-auth': { maturity: 'accepted-risk', verifiedCheckIds: [] } }),
    );
    const idpState = summary.get('idp-auth')!;
    expect(idpState.acceptedRisk).toBe(true);
    expect(idpState.readinessScore).toBe(0);
    expect(idpState.effective).toBe(false);
  });

  it('tolerates snapshots missing a source id without crashing', () => {
    const partial = createInitialAssessmentState('real');
    delete (partial as Record<string, SourceAssessmentState>)['idp-auth'];
    expect(() => buildVerificationSummary(sources, partial)).not.toThrow();
    expect(buildVerificationSummary(sources, partial).get('idp-auth')!.readinessScore).toBe(0);
  });
});

describe('createInitialAssessmentState seeding', () => {
  it('seeds demo sources as investigation-ready and leaves the rest not-collected', () => {
    const demo = createInitialAssessmentState('demo');
    for (const id of defaultDemoSourceIds) {
      expect(demo[id].maturity).toBe('investigation-ready');
      expect(demo[id].verifiedCheckIds.length).toBeGreaterThan(0);
    }
    const nonSeeded = sources.map((source) => source.id).filter((id) => !defaultDemoSourceIds.includes(id));
    for (const id of nonSeeded) {
      expect(demo[id].maturity).toBe('not-collected');
    }
  });

  it('seeds nothing in real mode', () => {
    const real = createInitialAssessmentState('real');
    for (const source of sources) {
      expect(real[source.id].maturity).toBe('not-collected');
      expect(real[source.id].verifiedCheckIds).toHaveLength(0);
    }
  });
});

describe('getScenarioStatus', () => {
  const scenario = catalogue.threatScenarios[0];
  const firstCritical = scenario.criticalSources[0];

  it('reports blind when no critical control is effective', () => {
    const summary = buildVerificationSummary(sources, createInitialAssessmentState('real'));
    expect(getScenarioStatus(scenario, summary).status).toBe('blind');
  });

  it('reports stopped/investigable only when every critical control is effective', () => {
    const readyState = stateWith(
      Object.fromEntries(
        scenario.criticalSources.map((id) => {
          const source = sources.find((entry) => entry.id === id)!;
          return [id, { maturity: 'investigation-ready', verifiedCheckIds: source.verificationChecks.filter((c) => c.priority === 'critical').map((c) => c.id), ...evidenceRecord }];
        }),
      ),
    );
    const summary = buildVerificationSummary(sources, readyState);
    expect(getScenarioStatus(scenario, summary).status).toBe('stopped');
  });

  it('reports partial when some but not all critical controls are effective', () => {
    const source = sources.find((entry) => entry.id === firstCritical)!;
    const summary = buildVerificationSummary(
      sources,
      stateWith({ [firstCritical]: { maturity: 'investigation-ready', verifiedCheckIds: source.verificationChecks.filter((c) => c.priority === 'critical').map((c) => c.id), ...evidenceRecord } }),
    );
    expect(getScenarioStatus(scenario, summary).status).toBe('partial');
  });

  it('reports substantial when every critical source has some evidence but at least one is not investigation-ready', () => {
    const substantialState = stateWith(
      Object.fromEntries(
        scenario.criticalSources.map((id) => {
          const source = sources.find((entry) => entry.id === id)!;
          return [id, { maturity: 'normalized-correlatable', verifiedCheckIds: source.verificationChecks.filter((c) => c.priority === 'critical').slice(0, 1).map((c) => c.id) }];
        }),
      ),
    );
    const summary = buildVerificationSummary(sources, substantialState);
    expect(getScenarioStatus(scenario, summary).status).toBe('substantial');
  });

  it('keeps accepted-risk sources from counting toward scenario readiness', () => {
    const source = sources.find((entry) => entry.id === firstCritical)!;
    const summary = buildVerificationSummary(
      sources,
      stateWith({ [firstCritical]: { maturity: 'accepted-risk', verifiedCheckIds: source.verificationChecks.filter((c) => c.priority === 'critical').map((c) => c.id) } }),
    );
    expect(getScenarioStatus(scenario, summary).status).toBe('blind');
  });
});
