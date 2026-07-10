import {
  attackChainStages,
  threatModel,
  type AttackChainStage,
  type AttackChainStageId,
  type ControlEffect,
  type EvidenceStatus,
  type GapType,
  type RemediationItem,
  type ScenarioStage,
  type Severity,
  type ThreatGap,
  type ThreatModel,
  type ThreatScenario,
} from '../data/threat-model';

/**
 * Computed view of the canonical Threat Model.
 *
 * Both renderers read from here. The 2D Attack Chain Map draws the lanes; the 3D Threat
 * Simulation animates the same outcomes. Neither is allowed to compute posture of its own,
 * which is what keeps the exported assessment and the visualisations in agreement.
 */

/**
 * Stage posture. `covered` is the only value that counts as coverage.
 *
 * An accepted-risk gap is a conscious decision to stay blind. It is neutral, it is visible,
 * and it never renders as covered. Precedence runs from the most severe unmet requirement
 * down, so a stage carrying both a telemetry gap and an accepted-risk gap reads as blind.
 *
 * `no-action` marks a stage the actor never enters in this scenario. It is not coverage and
 * not a gap, and it leaves the coverage denominator entirely.
 */
export type StagePosture = 'covered' | 'blind' | 'undetected' | 'unresolved' | 'accepted-risk' | 'no-action';

export type StopKind = 'blocked' | 'contained';

export interface StageOutcome {
  stageId: AttackChainStageId;
  stage: AttackChainStage;
  scenarioStage: ScenarioStage;
  order: number;
  posture: StagePosture;
  /** Whether the actor operates at this stage at all. */
  actorPresent: boolean;
  gapTypes: GapType[];
  /** A block control did its job. The action does not succeed. */
  blocked: boolean;
  /** A credible signal is raised. Detection alone never stops an attack. */
  detected: boolean;
  /** Friction was added. Response time was bought, nothing was stopped. */
  delayed: boolean;
  /** Blast radius was limited once the action was known. */
  contained: boolean;
  /** Containment happened, and it happened without a response gap in the way. */
  timelyContainment: boolean;
  /** Evidence survives well enough to reconstruct the action afterwards. */
  investigable: boolean;
  /** The chain cannot continue past this stage. */
  halted: boolean;
  stopKind: StopKind | null;
  evidenceHealth: Record<EvidenceStatus, number>;
  narration: string;
}

export interface ScenarioOutcome {
  scenario: ThreatScenario;
  stages: StageOutcome[];
  /** First stage that stops the chain, or null when the actor reaches the end. */
  stoppedAtStageId: AttackChainStageId | null;
  stopKind: StopKind | null;
  /** Stages the actor actually reaches, plus the defender's Response stage, which always runs. */
  reachedStageIds: AttackChainStageId[];
  coveredStages: number;
  acceptedRiskStages: number;
  noActionStages: number;
  totalStages: number;
  /** Stages the actor operates in. The coverage denominator. */
  inPathStages: number;
  /** Covered stages over in-path stages. Accepted risk contributes nothing. */
  coverageRatio: number;
  gapCounts: Record<GapType, number>;
  highestSeverity: Severity | null;
  gapRegister: GapRegisterEntry[];
  remediationQueue: RemediationQueueEntry[];
}

export interface GapRegisterEntry extends ThreatGap {
  stageId: AttackChainStageId;
  stageLabel: string;
}

export interface RemediationQueueEntry extends RemediationItem {
  stageId: AttackChainStageId;
  stageLabel: string;
  severity: Severity;
  gapTypes: GapType[];
}

export interface SimulationEvent {
  stageId: AttackChainStageId;
  stageLabel: string;
  order: number;
  posture: StagePosture;
  /** Effects to animate at this stage, in the order a viewer should read them. */
  effects: ControlEffect[];
  halted: boolean;
  stopKind: StopKind | null;
  /** Telemetry gap means an unlit zone: the stage is not illuminated in the scene. */
  lit: boolean;
  /** False for stages past the halt. Those are drawn dim: the actor never gets there. */
  reached: boolean;
  narration: string;
}

const severityRank: Record<Severity, number> = { critical: 0, high: 1, medium: 2, low: 3 };
const gapTypeRank: Record<GapType, number> = { telemetry: 0, detection: 1, response: 2, 'accepted-risk': 3 };
const effectOrder: ControlEffect[] = ['delay', 'detect', 'investigate', 'block', 'contain'];

export const postureLabels: Record<StagePosture, string> = {
  covered: 'Covered',
  blind: 'Blind zone',
  undetected: 'Passes undetected',
  unresolved: 'Alert without containment',
  'accepted-risk': 'Accepted risk',
  'no-action': 'Actor takes no action',
};

export const postureMeanings: Record<StagePosture, string> = {
  covered: 'Evidence exists, a tested signal fires, and the response path is owned.',
  blind: 'A telemetry gap leaves this stage unlit. The move is not observed at all.',
  undetected: 'Telemetry exists but no credible alert fires. The move passes.',
  unresolved: 'The move is visible, but containment is late, unowned, or absent.',
  'accepted-risk': 'A tolerated blind spot. Visible, neutral, and never counted as coverage.',
  'no-action': 'The actor never operates here. Not coverage, not a gap, and outside the coverage denominator.',
};

const stageById = new Map<AttackChainStageId, AttackChainStage>(attackChainStages.map((stage) => [stage.id, stage]));

/** The defender's stage. It always runs, whatever stopped the actor earlier. */
const DEFENDER_STAGE: AttackChainStageId = 'response';

/** Accepted risk is a gap, never coverage. This is the single place that decides. */
export function isCovered(posture: StagePosture): boolean {
  return posture === 'covered';
}

export function stagePosture(gapTypes: GapType[], actorPresent = true): StagePosture {
  if (gapTypes.includes('telemetry')) return 'blind';
  if (gapTypes.includes('detection')) return 'undetected';
  if (gapTypes.includes('response')) return 'unresolved';
  if (gapTypes.includes('accepted-risk')) return 'accepted-risk';
  return actorPresent ? 'covered' : 'no-action';
}

function narrate(posture: StagePosture, blocked: boolean, contained: boolean, delayed: boolean): string {
  if (posture === 'no-action') return 'The actor never operates here. The estate can prove the negative.';
  if (blocked) return 'Strong preventive control. The action would be blocked and the chain would stop here.';
  if (contained) {
    return posture === 'unresolved'
      ? 'Late containment would stop the chain here, but missing evidence would weaken confidence and scoping.'
      : 'Strong containment would stop the chain here and preserve a defensible response path.';
  }
  switch (posture) {
    case 'blind':
      return delayed ? 'Unlit. Friction slows the move; nothing observes it.' : 'Unlit. No telemetry records this move.';
    case 'undetected':
      return 'Observed but never alerted. The move passes without a credible signal.';
    case 'unresolved':
      return 'Alerted, then nothing. No timely containment or named owner.';
    case 'accepted-risk':
      return 'A tolerated blind spot. Recorded as a decision, counted as no coverage.';
    default:
      return delayed ? 'Observed, alerted, and slowed. Response time is real.' : 'Observed, alerted, and owned.';
  }
}

export function buildStageOutcome(scenarioStage: ScenarioStage): StageOutcome {
  const stage = stageById.get(scenarioStage.stageId);
  if (!stage) throw new Error(`Unknown attack chain stage: ${scenarioStage.stageId}`);

  const actorPresent = scenarioStage.actorPresent ?? true;
  const gapTypes = [...new Set(scenarioStage.gaps.map((gap) => gap.type))].sort((a, b) => gapTypeRank[a] - gapTypeRank[b]);
  const posture = stagePosture(gapTypes, actorPresent);
  const has = (effect: ControlEffect, outcomes: readonly string[]) =>
    scenarioStage.controls.some((control) => control.effect === effect && outcomes.includes(control.outcome));

  // A control can only stop an actor who is actually there. A closed door the actor never
  // tried is not a block, and counting it as one would manufacture coverage.
  const blocked = actorPresent && has('block', ['holds']);
  const contained = actorPresent && has('contain', ['holds']);
  // Detection is only real when the events are there and an analytic actually tests them.
  const detected = has('detect', ['holds', 'partial']) && !gapTypes.includes('telemetry') && !gapTypes.includes('detection');
  const delayed = has('delay', ['holds', 'partial']);
  const investigable = has('investigate', ['holds']);

  const evidenceHealth: Record<EvidenceStatus, number> = { present: 0, partial: 0, absent: 0 };
  for (const evidence of scenarioStage.evidence) evidenceHealth[evidence.status] += 1;

  return {
    stageId: scenarioStage.stageId,
    stage,
    scenarioStage,
    order: stage.order,
    posture,
    actorPresent,
    gapTypes,
    blocked,
    detected,
    delayed,
    contained,
    timelyContainment: contained && !gapTypes.includes('response'),
    investigable,
    halted: blocked || contained,
    stopKind: blocked ? 'blocked' : contained ? 'contained' : null,
    evidenceHealth,
    narration: narrate(posture, blocked, contained, delayed),
  };
}

export function buildScenarioOutcome(scenario: ThreatScenario): ScenarioOutcome {
  const stages = scenario.stages.map(buildStageOutcome).sort((a, b) => a.order - b.order);
  const stopIndex = stages.findIndex((outcome) => outcome.halted);
  const stopStage = stopIndex >= 0 ? stages[stopIndex] : null;

  const gapCounts: Record<GapType, number> = { telemetry: 0, detection: 0, response: 0, 'accepted-risk': 0 };
  const gapRegister: GapRegisterEntry[] = [];
  const remediationQueue: RemediationQueueEntry[] = [];

  for (const outcome of stages) {
    const gapsById = new Map(outcome.scenarioStage.gaps.map((gap) => [gap.id, gap]));
    for (const gap of outcome.scenarioStage.gaps) {
      gapCounts[gap.type] += 1;
      gapRegister.push({ ...gap, stageId: outcome.stageId, stageLabel: outcome.stage.label });
    }
    for (const item of outcome.scenarioStage.remediation) {
      const linked = item.gapIds.map((id) => gapsById.get(id)).filter((gap): gap is ThreatGap => Boolean(gap));
      const severity = linked.reduce<Severity>(
        (worst, gap) => (severityRank[gap.severity] < severityRank[worst] ? gap.severity : worst),
        'low',
      );
      remediationQueue.push({
        ...item,
        stageId: outcome.stageId,
        stageLabel: outcome.stage.label,
        severity,
        gapTypes: [...new Set(linked.map((gap) => gap.type))],
      });
    }
  }

  gapRegister.sort((a, b) => severityRank[a.severity] - severityRank[b.severity] || gapTypeRank[a.type] - gapTypeRank[b.type]);
  remediationQueue.sort((a, b) => severityRank[a.severity] - severityRank[b.severity] || a.targetDate.localeCompare(b.targetDate));

  const coveredStages = stages.filter((outcome) => isCovered(outcome.posture)).length;
  const acceptedRiskStages = stages.filter((outcome) => outcome.posture === 'accepted-risk').length;
  const noActionStages = stages.filter((outcome) => outcome.posture === 'no-action').length;
  const inPathStages = stages.length - noActionStages;
  const highestSeverity =
    gapRegister.length === 0
      ? null
      : gapRegister.reduce<Severity>((worst, gap) => (severityRank[gap.severity] < severityRank[worst] ? gap.severity : worst), 'low');

  // The actor stops where they are stopped. The defender's Response stage runs regardless.
  const reached = new Set((stopIndex >= 0 ? stages.slice(0, stopIndex + 1) : stages).map((outcome) => outcome.stageId));
  reached.add(DEFENDER_STAGE);

  return {
    scenario,
    stages,
    stoppedAtStageId: stopStage?.stageId ?? null,
    stopKind: stopStage?.stopKind ?? null,
    reachedStageIds: stages.map((outcome) => outcome.stageId).filter((stageId) => reached.has(stageId)),
    coveredStages,
    acceptedRiskStages,
    noActionStages,
    totalStages: stages.length,
    inPathStages,
    coverageRatio: inPathStages === 0 ? 0 : coveredStages / inPathStages,
    gapCounts,
    highestSeverity,
    gapRegister,
    remediationQueue,
  };
}

/** Ordered effects for a stage, so the 3D scene animates what each control actually does. */
export function stageEffects(outcome: StageOutcome): ControlEffect[] {
  const present = new Set(
    outcome.scenarioStage.controls.filter((control) => control.outcome !== 'bypassed').map((control) => control.effect),
  );
  return effectOrder.filter((effect) => present.has(effect));
}

/** The shared timeline. The 3D scene animates this; the 2D map annotates the same facts. */
export function simulationTimeline(scenario: ThreatScenario): SimulationEvent[] {
  const outcome = buildScenarioOutcome(scenario);
  const stopIndex = outcome.stages.findIndex((stage) => stage.halted);
  const reached = new Set(outcome.reachedStageIds);

  return outcome.stages.map((stage, index) => ({
    stageId: stage.stageId,
    stageLabel: stage.stage.label,
    order: stage.order,
    posture: stage.posture,
    effects: stageEffects(stage),
    halted: stopIndex >= 0 && index === stopIndex,
    stopKind: stopIndex >= 0 && index === stopIndex ? stage.stopKind : null,
    lit: !stage.gapTypes.includes('telemetry'),
    reached: reached.has(stage.stageId),
    narration: stage.narration,
  }));
}

export interface ModelSummary {
  scenarios: number;
  internalScenarios: number;
  cyberScenarios: number;
  gapCounts: Record<GapType, number>;
  /** Stages that reach `covered`. Accepted risk is excluded by definition. */
  coveredStages: number;
  totalStages: number;
  inPathStages: number;
  acceptedRiskStages: number;
  openRemediation: number;
}

export function buildModelSummary(model: ThreatModel = threatModel): ModelSummary {
  const outcomes = model.scenarios.map(buildScenarioOutcome);
  const gapCounts: Record<GapType, number> = { telemetry: 0, detection: 0, response: 0, 'accepted-risk': 0 };
  for (const outcome of outcomes) {
    for (const type of Object.keys(gapCounts) as GapType[]) gapCounts[type] += outcome.gapCounts[type];
  }
  return {
    scenarios: outcomes.length,
    internalScenarios: outcomes.filter((outcome) => outcome.scenario.kind === 'internal').length,
    cyberScenarios: outcomes.filter((outcome) => outcome.scenario.kind === 'cyber').length,
    gapCounts,
    coveredStages: outcomes.reduce((sum, outcome) => sum + outcome.coveredStages, 0),
    totalStages: outcomes.reduce((sum, outcome) => sum + outcome.totalStages, 0),
    inPathStages: outcomes.reduce((sum, outcome) => sum + outcome.inPathStages, 0),
    acceptedRiskStages: outcomes.reduce((sum, outcome) => sum + outcome.acceptedRiskStages, 0),
    openRemediation: outcomes.reduce((sum, outcome) => sum + outcome.remediationQueue.length, 0),
  };
}

/** Exportable, printable shape. The 2D map is the authoritative view of exactly this object. */
export function serializeScenario(scenario: ThreatScenario): string {
  const outcome = buildScenarioOutcome(scenario);
  return JSON.stringify(
    {
      modelVersion: threatModel.version,
      safety: threatModel.safety,
      scenario: {
        id: scenario.id,
        kind: scenario.kind,
        title: scenario.title,
        actor: scenario.actor,
        objective: scenario.objective,
      },
      coverage: {
        coveredStages: outcome.coveredStages,
        acceptedRiskStages: outcome.acceptedRiskStages,
        noActionStages: outcome.noActionStages,
        inPathStages: outcome.inPathStages,
        totalStages: outcome.totalStages,
        note: 'Accepted risk contributes no coverage. Stages the actor never enters are outside the denominator.',
      },
      stoppedAtStage: outcome.stoppedAtStageId,
      stopKind: outcome.stopKind,
      stages: outcome.stages.map((stage) => ({
        stage: stage.stageId,
        posture: stage.posture,
        action: stage.scenarioStage.action,
        evidence: stage.scenarioStage.evidence,
        controls: stage.scenarioStage.controls,
        gaps: stage.scenarioStage.gaps,
        remediation: stage.scenarioStage.remediation,
      })),
      gapRegister: outcome.gapRegister,
      remediationQueue: outcome.remediationQueue,
    },
    null,
    2,
  );
}
