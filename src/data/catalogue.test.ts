import { describe, expect, it } from 'vitest';

import { catalogue, logSources, riskVectors } from './catalogue';

describe('threat-scenario catalogue seed data', () => {
  it('exposes non-empty sources and risk vectors', () => {
    expect(catalogue.version).toBe('seed-0.2.0');
    expect(logSources.length).toBeGreaterThan(0);
    expect(riskVectors.length).toBeGreaterThan(0);
  });

  it('only references defined log source IDs from evidence mappings', () => {
    const sourceIds = new Set(logSources.map((source) => source.id));

    for (const vector of riskVectors) {
      expect(vector.investigationQuestions.length).toBeGreaterThan(0);

      for (const question of vector.investigationQuestions) {
        expect(question.evidence.length).toBeGreaterThan(0);

        for (const mapping of question.evidence) {
          expect(sourceIds.has(mapping.sourceId)).toBe(true);
        }
      }
    }
  });

  it('defines prioritized verification checks and scenario flow controls', () => {
    for (const source of logSources) {
      expect(source.verificationChecks.length).toBeGreaterThan(0);
      expect(source.verificationChecks.some((check) => check.priority === 'critical' || check.priority === 'recommended')).toBe(true);
      for (const check of source.verificationChecks) {
        expect(check.verificationQuestion).toContain('?');
        expect(check.requiredFields.length).toBeGreaterThan(0);
        expect(check.objective.length).toBeGreaterThan(10);
      }
    }

    expect(logSources.find((source) => source.id === 'email')?.verificationChecks.some((check) => check.id === 'email-login-logout')).toBe(true);
    expect(catalogue.threatFlow.length).toBeGreaterThan(3);
    expect(catalogue.threatScenarios.length).toBeGreaterThan(3);
  });

  it('references only defined vector and source IDs from scenarios, with no orphaned vectors', () => {
    const vectorIds = new Set(riskVectors.map((vector) => vector.id));
    const sourceIds = new Set(logSources.map((source) => source.id));
    const flowIds = new Set(catalogue.threatFlow.map((step) => step.id));
    const referencedVectors = new Set<string>();

    for (const scenario of catalogue.threatScenarios) {
      for (const vectorId of scenario.vectorIds) {
        expect(vectorIds.has(vectorId)).toBe(true);
        referencedVectors.add(vectorId);
      }
      for (const sourceId of [...scenario.criticalSources, ...scenario.recommendedSources]) {
        expect(sourceIds.has(sourceId)).toBe(true);
      }
      for (const flowId of scenario.flowStepIds) {
        expect(flowIds.has(flowId)).toBe(true);
      }
    }

    // Every risk vector should surface in at least one scenario (no orphans).
    for (const vector of riskVectors) {
      expect(referencedVectors.has(vector.id)).toBe(true);
    }
  });

  it('gives every risk vector an ATT&CK-referenced alignment note', () => {
    for (const vector of riskVectors) {
      expect(vector.techniqueAlignment).toMatch(/ATT&CK|adversary-technique/);
    }
  });
});
