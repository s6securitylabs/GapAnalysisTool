import { describe, expect, it } from 'vitest';

import { catalogue } from './catalogue';
import { attackChainStages, gapTypeLabels, threatModel, type GapType, type ThreatScenarioTheme } from './threat-model';

const CANONICAL_CHAIN = ['Preparation', 'Access', 'Misuse', 'Collection', 'Exfiltration', 'Concealment', 'Response'];

describe('canonical threat model', () => {
  it('uses the accepted attack chain in order', () => {
    expect(attackChainStages.map((stage) => stage.label)).toEqual(CANONICAL_CHAIN);
    expect(attackChainStages.map((stage) => stage.order)).toEqual([1, 2, 3, 4, 5, 6, 7]);
  });

  it('carries both internal and external cyber scenarios', () => {
    const kinds = new Set(threatModel.scenarios.map((scenario) => scenario.kind));
    expect(kinds).toEqual(new Set(['internal', 'cyber']));
    expect(threatModel.scenarios.filter((scenario) => scenario.kind === 'internal').length).toBeGreaterThan(0);
    expect(threatModel.scenarios.filter((scenario) => scenario.kind === 'cyber').length).toBeGreaterThan(0);
    expect(threatModel.scenarios).toHaveLength(17);
    expect(threatModel.scenarios.filter((scenario) => scenario.kind === 'internal')).toHaveLength(9);
    expect(threatModel.scenarios.filter((scenario) => scenario.kind === 'cyber')).toHaveLength(8);
  });

  it('keeps scenario identifiers unique', () => {
    const ids = threatModel.scenarios.map((scenario) => scenario.id);
    expect(new Set(ids).size).toBe(ids.length);
  });

  it('gives every scenario a fictional business story with impact, considerations, and an outcome', () => {
    for (const scenario of threatModel.scenarios) {
      expect(scenario.story.title.trim()).not.toBe('');
      expect(scenario.story.narrative.length).toBeGreaterThan(120);
      expect(scenario.story.businessImpact.length).toBeGreaterThan(80);
      expect(scenario.story.considerations.length).toBeGreaterThanOrEqual(3);
      expect(scenario.story.outcome.length).toBeGreaterThan(80);
    }
  });

  it('covers major external cyber loss events', () => {
    const cyberIds = new Set(threatModel.scenarios.filter((scenario) => scenario.kind === 'cyber').map((scenario) => scenario.id));
    expect(cyberIds).toEqual(new Set([
      'cyber-phishing-to-ransomware',
      'cyber-saas-token-theft',
      'business-email-compromise',
      'public-api-data-breach',
      'software-supply-chain-compromise',
      'public-cloud-storage-exposure',
      'availability-extortion-ddos',
      'detection-pipeline-suppression',
    ]));
  });

  it('includes indicative ATT&CK references for adversarial curated scenarios', () => {
    for (const id of ['third-party-cloud-export', 'break-glass-credential-misuse', 'detection-pipeline-suppression']) {
      const scenario = threatModel.scenarios.find((item) => item.id === id);
      expect(scenario).toBeDefined();
      expect(scenario?.stages.some((stage) => /^T\d{4}(?:\.\d{3})?\b/.test(stage.action.technique ?? ''))).toBe(true);
    }
  });

  it('covers the required insider, third-party, cloud, ransomware, and engineering themes', () => {
    const requiredThemes: ThreatScenarioTheme[] = [
      'insider-misuse',
      'privileged-admin',
      'data-exfiltration',
      'sabotage',
      'credential-misuse',
      'third-party',
      'ransomware',
      'cloud-saas',
      'detection-response',
    ];
    const seen = new Set(threatModel.scenarios.flatMap((scenario) => scenario.themes));
    expect(seen).toEqual(new Set(requiredThemes));
    for (const scenario of threatModel.scenarios) expect(scenario.themes.length).toBeGreaterThan(0);
  });

  it('models every scenario across every stage of the chain exactly once', () => {
    for (const scenario of threatModel.scenarios) {
      const ids = scenario.stages.map((stage) => stage.stageId);
      expect(new Set(ids).size).toBe(ids.length);
      expect([...ids].sort()).toEqual([...attackChainStages.map((stage) => stage.id)].sort());
      for (const stage of scenario.stages) {
        expect(stage.action.summary.trim()).not.toBe('');
        expect(stage.action.detail.trim()).not.toBe('');
        if (stage.actorPresent !== false) {
          expect(stage.evidence.length).toBeGreaterThan(0);
          expect(stage.controls.length).toBeGreaterThan(0);
        }
      }
    }
  });

  it('maps every evidence reference to a real log source in the catalogue', () => {
    const sourceIds = new Set(catalogue.logSources.map((source) => source.id));
    for (const scenario of threatModel.scenarios) {
      for (const stage of scenario.stages) {
        for (const evidence of stage.evidence) {
          expect(sourceIds.has(evidence.sourceId)).toBe(true);
        }
      }
    }
  });

  it('keeps gap, control, and remediation identifiers unique across the model', () => {
    const gapIds: string[] = [];
    const controlIds: string[] = [];
    const remediationIds: string[] = [];
    for (const scenario of threatModel.scenarios) {
      for (const stage of scenario.stages) {
        gapIds.push(...stage.gaps.map((gap) => gap.id));
        controlIds.push(...stage.controls.map((control) => control.id));
        remediationIds.push(...stage.remediation.map((item) => item.id));
      }
    }
    expect(new Set(gapIds).size).toBe(gapIds.length);
    expect(new Set(controlIds).size).toBe(controlIds.length);
    expect(new Set(remediationIds).size).toBe(remediationIds.length);
  });

  it('links every remediation item to gaps declared on the same stage', () => {
    for (const scenario of threatModel.scenarios) {
      for (const stage of scenario.stages) {
        const stageGapIds = new Set(stage.gaps.map((gap) => gap.id));
        for (const item of stage.remediation) {
          expect(item.gapIds.length).toBeGreaterThan(0);
          for (const gapId of item.gapIds) expect(stageGapIds.has(gapId)).toBe(true);
        }
      }
    }
  });

  it('exercises all four accepted gap types somewhere in the model', () => {
    const seen = new Set<GapType>();
    for (const scenario of threatModel.scenarios) {
      for (const stage of scenario.stages) {
        for (const gap of stage.gaps) seen.add(gap.type);
      }
    }
    expect(seen).toEqual(new Set(Object.keys(gapTypeLabels) as GapType[]));
  });

  it('queues no remediation against an accepted-risk gap, because accepted risk is a decision', () => {
    for (const scenario of threatModel.scenarios) {
      for (const stage of scenario.stages) {
        const acceptedIds = new Set(stage.gaps.filter((gap) => gap.type === 'accepted-risk').map((gap) => gap.id));
        for (const item of stage.remediation) {
          for (const gapId of item.gapIds) expect(acceptedIds.has(gapId)).toBe(false);
        }
      }
    }
  });

  it('states the public-demo safety boundary on the model itself', () => {
    expect(threatModel.safety).toMatch(/Demo data only/i);
    expect(threatModel.safety).toMatch(/tenant identifiers/i);
  });

  it('avoids generic readiness-control labels on curated stages', () => {
    for (const scenario of threatModel.scenarios) {
      for (const stage of scenario.stages) {
        for (const control of stage.controls) {
          expect(control.name).not.toMatch(/readiness control$/i);
        }
      }
    }
  });
});
