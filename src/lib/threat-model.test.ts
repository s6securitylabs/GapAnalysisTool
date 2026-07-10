import { describe, expect, it } from 'vitest';

import { scenarioById, threatModel } from '../data/threat-model';
import {
  buildModelSummary,
  buildScenarioOutcome,
  isCovered,
  postureLabels,
  serializeScenario,
  simulationTimeline,
  stagePosture,
  type StagePosture,
} from './threat-model';

function outcomeFor(id: string) {
  const scenario = scenarioById(id);
  if (!scenario) throw new Error(`Missing scenario ${id}`);
  return buildScenarioOutcome(scenario);
}

describe('stage posture', () => {
  it('ranks gap types so the most severe unmet requirement decides the stage', () => {
    expect(stagePosture(['telemetry', 'accepted-risk'])).toBe('blind');
    expect(stagePosture(['detection', 'response'])).toBe('undetected');
    expect(stagePosture(['response'])).toBe('unresolved');
    expect(stagePosture([])).toBe('covered');
  });

  it('never treats accepted risk as coverage', () => {
    expect(stagePosture(['accepted-risk'])).toBe('accepted-risk');
    expect(isCovered('accepted-risk')).toBe(false);
    expect(postureLabels['accepted-risk']).toBe('Accepted risk');
  });

  it('treats a stage the actor never enters as neither coverage nor a gap', () => {
    expect(stagePosture([], false)).toBe('no-action');
    expect(isCovered('no-action')).toBe(false);
  });

  it('only calls a stage covered when it carries no gap at all', () => {
    const postures: StagePosture[] = ['covered', 'blind', 'undetected', 'unresolved', 'accepted-risk', 'no-action'];
    expect(postures.filter(isCovered)).toEqual(['covered']);
  });
});

describe('scenario outcome', () => {
  it('keeps accepted risk out of the coverage numerator', () => {
    const outcome = outcomeFor('internal-privileged-sabotage');
    expect(outcome.acceptedRiskStages).toBeGreaterThan(0);
    const acceptedStages = outcome.stages.filter((stage) => stage.posture === 'accepted-risk');
    expect(acceptedStages.every((stage) => !isCovered(stage.posture))).toBe(true);
    expect(outcome.coveredStages + outcome.acceptedRiskStages).toBeLessThanOrEqual(outcome.inPathStages);
  });

  it('excludes stages the actor never enters from the coverage denominator', () => {
    const outcome = outcomeFor('internal-privileged-sabotage');
    expect(outcome.noActionStages).toBe(2);
    expect(outcome.inPathStages).toBe(outcome.totalStages - outcome.noActionStages);
    expect(outcome.coverageRatio).toBeCloseTo(outcome.coveredStages / outcome.inPathStages, 5);
  });

  it('does not let a control halt a stage the actor never entered', () => {
    const outcome = outcomeFor('internal-privileged-sabotage');
    const exfiltration = outcome.stages.find((stage) => stage.stageId === 'exfiltration');
    // The egress restriction holds, but nothing was attempted, so nothing was stopped.
    expect(exfiltration?.scenarioStage.controls.some((control) => control.effect === 'block' && control.outcome === 'holds')).toBe(true);
    expect(exfiltration?.blocked).toBe(false);
    expect(exfiltration?.halted).toBe(false);
  });

  it('lets a detection-only control observe without stopping the actor', () => {
    const outcome = outcomeFor('internal-pre-resignation-exfiltration');
    const collection = outcome.stages.find((stage) => stage.stageId === 'collection');
    expect(collection?.posture).toBe('undetected');
    expect(collection?.halted).toBe(false);
    expect(collection?.detected).toBe(false);
  });

  it('marks a telemetry gap as a blind zone that the simulation must leave unlit', () => {
    const events = simulationTimeline(threatModel.scenarios[0]);
    const exfiltration = events.find((event) => event.stageId === 'exfiltration');
    expect(exfiltration?.posture).toBe('blind');
    expect(exfiltration?.lit).toBe(false);
  });

  it('runs the internal exfiltration chain to the end because nothing blocks or contains it', () => {
    const outcome = outcomeFor('internal-pre-resignation-exfiltration');
    expect(outcome.stoppedAtStageId).toBeNull();
    expect(outcome.stopKind).toBeNull();
    expect(outcome.reachedStageIds).toHaveLength(outcome.totalStages);
  });

  it('stops the ransomware chain at concealment where the immutable backup lock holds', () => {
    const outcome = outcomeFor('cyber-phishing-to-ransomware');
    expect(outcome.stoppedAtStageId).toBe('concealment');
    expect(outcome.stopKind).toBe('blocked');
    // The conditional-access block is partial, so it must not halt the chain at Access.
    const access = outcome.stages.find((stage) => stage.stageId === 'access');
    expect(access?.halted).toBe(false);
  });

  it('leaves stages past the halt unreached, while the defender stage still runs', () => {
    const stopsAtAccess = buildScenarioOutcome({
      ...threatModel.scenarios[0],
      stages: threatModel.scenarios[0].stages.map((stage) =>
        stage.stageId === 'access'
          ? { ...stage, controls: [{ id: 'test-block', name: 'Test block', effect: 'block', outcome: 'holds', confidence: 'high', note: 'Synthetic.' }] }
          : stage,
      ),
    });

    expect(stopsAtAccess.stoppedAtStageId).toBe('access');
    expect(stopsAtAccess.reachedStageIds).toEqual(['preparation', 'access', 'response']);
    expect(simulationTimeline(stopsAtAccess.scenario).filter((event) => !event.reached).map((event) => event.stageId)).toEqual([
      'misuse',
      'collection',
      'exfiltration',
      'concealment',
    ]);
  });

  it('always reaches the defender response stage, whatever stopped the actor earlier', () => {
    for (const scenario of threatModel.scenarios) {
      expect(buildScenarioOutcome(scenario).reachedStageIds).toContain('response');
    }
  });

  it('separates late containment from timely containment', () => {
    const outcome = outcomeFor('cyber-saas-token-theft');
    const response = outcome.stages.find((stage) => stage.stageId === 'response');
    expect(response?.contained).toBe(true);
    expect(response?.posture).toBe('unresolved');
    expect(response?.timelyContainment).toBe(false);
    expect(response?.narration).toMatch(/late/i);
  });

  it('ranks the gap register by severity and the remediation queue by the worst linked gap', () => {
    const outcome = outcomeFor('cyber-phishing-to-ransomware');
    expect(outcome.gapRegister[0].severity).toBe('critical');
    expect(outcome.remediationQueue[0].severity).toBe('critical');
    expect(outcome.remediationQueue.every((item) => item.gapTypes.length > 0)).toBe(true);
  });
});

describe('simulation timeline', () => {
  it('orders every stage of the chain and carries the same postures as the map', () => {
    for (const scenario of threatModel.scenarios) {
      const outcome = buildScenarioOutcome(scenario);
      const events = simulationTimeline(scenario);
      expect(events.map((event) => event.order)).toEqual([1, 2, 3, 4, 5, 6, 7]);
      expect(events.map((event) => event.posture)).toEqual(outcome.stages.map((stage) => stage.posture));
    }
  });

  it('marks exactly one halt, and only where the model says the chain stops', () => {
    for (const scenario of threatModel.scenarios) {
      const outcome = buildScenarioOutcome(scenario);
      const halts = simulationTimeline(scenario).filter((event) => event.halted);
      expect(halts).toHaveLength(outcome.stoppedAtStageId ? 1 : 0);
      if (outcome.stoppedAtStageId) expect(halts[0].stageId).toBe(outcome.stoppedAtStageId);
    }
  });

  it('never animates a bypassed control', () => {
    for (const scenario of threatModel.scenarios) {
      const events = simulationTimeline(scenario);
      for (const stage of scenario.stages) {
        const event = events.find((item) => item.stageId === stage.stageId);
        const bypassedOnly = stage.controls
          .filter((control) => control.outcome === 'bypassed')
          .filter((control) => !stage.controls.some((other) => other.effect === control.effect && other.outcome !== 'bypassed'))
          .map((control) => control.effect);
        for (const effect of bypassedOnly) expect(event?.effects).not.toContain(effect);
      }
    }
  });
});

describe('model summary and export', () => {
  it('summarises internal and cyber scenarios with the four accepted gap types', () => {
    const summary = buildModelSummary();
    expect(summary.scenarios).toBe(threatModel.scenarios.length);
    expect(summary.internalScenarios).toBeGreaterThan(0);
    expect(summary.cyberScenarios).toBeGreaterThan(0);
    expect(Object.values(summary.gapCounts).every((count) => count > 0)).toBe(true);
    expect(summary.coveredStages).toBeLessThan(summary.inPathStages);
  });

  it('exports a printable object that states accepted risk contributes no coverage', () => {
    const exported = JSON.parse(serializeScenario(threatModel.scenarios[0]));
    expect(exported.modelVersion).toBe(threatModel.version);
    expect(exported.coverage.note).toMatch(/Accepted risk contributes no coverage/);
    expect(exported.safety).toMatch(/Demo data only/i);
    expect(exported.stages).toHaveLength(7);
    expect(exported.stages[0].stage).toBe('preparation');
  });
});
