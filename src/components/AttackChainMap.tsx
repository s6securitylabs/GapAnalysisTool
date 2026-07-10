import {
  controlEffectLabels,
  gapTypeLabels,
  type EvidenceStatus,
  type ThreatScenario,
} from '../data/threat-model';
import { buildScenarioOutcome, postureLabels, type StageOutcome } from '../lib/threat-model';
import type { LogSource, LogSourceId } from '../data/catalogue';

/**
 * 2D Attack Chain Map — the authoritative view.
 *
 * Everything the assessment claims is legible here: stage by stage, what the actor does,
 * what evidence exists, what each control actually does, which gaps are open and of what
 * type, and what remediation is queued. This is the view that prints and exports. The 3D
 * simulation explores the same object; it never adds to it.
 */

const evidenceStatusLabels: Record<EvidenceStatus, string> = {
  present: 'Present',
  partial: 'Partial',
  absent: 'Absent',
};

const lanes = [
  { id: 'action', label: 'Attack action' },
  { id: 'evidence', label: 'Evidence' },
  { id: 'controls', label: 'Controls' },
  { id: 'gaps', label: 'Gaps' },
  { id: 'remediation', label: 'Remediation' },
] as const;

export function AttackChainMap({
  scenario,
  sourceById,
}: {
  scenario: ThreatScenario;
  sourceById: Map<LogSourceId, LogSource>;
}) {
  const outcome = buildScenarioOutcome(scenario);
  const reached = new Set(outcome.reachedStageIds);

  return (
    <div className="attack-chain-map">
      <div className="chain-readout">
        <span className="chain-readout-item">
          <strong>{outcome.coveredStages}</strong> of {outcome.inPathStages} in-path stages covered
        </span>
        <span className="chain-readout-item">
          <strong>{outcome.acceptedRiskStages}</strong> accepted risk (never counted as covered)
        </span>
        <span className="chain-readout-item">
          <strong>{outcome.gapRegister.length}</strong> open gaps
        </span>
        <span className={`chain-readout-item chain-stop ${outcome.stopKind ?? 'open'}`}>
          {outcome.stoppedAtStageId
            ? `Chain stops at ${outcome.stages.find((stage) => stage.stageId === outcome.stoppedAtStageId)?.stage.label}`
            : 'Chain runs to the end of the model'}
        </span>
      </div>

      <details className="visual-legend attack-chain-legend" open>
        <summary>2D map legend</summary>
        <div className="legend-grid compact-legend">
          <div><span className="legend-swatch covered" /> Covered / stopped</div>
          <div><span className="legend-swatch unresolved" /> Gap or partial evidence</div>
          <div><span className="legend-swatch undetected" /> Undetected path</div>
          <div><span className="legend-swatch accepted-risk" /> Accepted risk, no coverage</div>
          <div><span className="evidence-dot present" /> Evidence present</div>
          <div><span className="evidence-dot partial" /> Evidence partial</div>
          <div><span className="evidence-dot absent" /> Evidence absent</div>
        </div>
      </details>

      <figure className="attack-chain-flow" aria-labelledby={`attack-chain-caption-${scenario.id}`}>
        <figcaption id={`attack-chain-caption-${scenario.id}`}>
          <strong>Scenario path: {scenario.title}</strong>
          <span>Follow the arrows from actor preparation through defender response. Each stage shows evidence, control, and gap readiness at a glance.</span>
        </figcaption>
        <ol aria-label={`Directional attack chain for ${scenario.title}`}>
          {outcome.stages.map((stage) => {
            const evidenceReady = stage.evidenceHealth.present;
            const evidenceTotal = stage.scenarioStage.evidence.length;
            const holdingControls = stage.scenarioStage.controls.filter((control) => control.outcome === 'holds').length;
            const reachedStage = reached.has(stage.stageId);
            return (
              <li className={`attack-flow-stage ${stage.posture} ${reachedStage ? 'reached' : 'beyond-stop'}`} key={stage.stageId}>
                <div className="attack-flow-heading">
                  <span className="attack-flow-order">{stage.order}</span>
                  <span className="scenario-marker">{stage.stageId === 'response' ? 'Defender' : 'Actor'}</span>
                </div>
                <strong>{stage.stage.label}</strong>
                <span className="attack-flow-action">{stage.scenarioStage.action.summary}</span>
                <dl>
                  <div>
                    <dt>Evidence</dt>
                    <dd>{evidenceReady}/{evidenceTotal} ready</dd>
                  </div>
                  <div>
                    <dt>Controls</dt>
                    <dd>{holdingControls}/{stage.scenarioStage.controls.length} holding</dd>
                  </div>
                  <div>
                    <dt>Gaps</dt>
                    <dd>{stage.scenarioStage.gaps.length}</dd>
                  </div>
                </dl>
                <span className={`posture-badge ${stage.posture}`}>{postureLabels[stage.posture]}</span>
                {stage.halted && <span className="attack-flow-stop">Chain stops here</span>}
              </li>
            );
          })}
        </ol>
      </figure>

      <div className="chain-scroll" tabIndex={0} role="region" aria-label={`Attack chain map for ${scenario.title}`}>
        <div className="chain-grid" style={{ ['--stage-count' as string]: String(outcome.stages.length) }} role="table">
          <div className="chain-row" role="row">
            <div className="lane-label lane-corner" role="columnheader">
              Stage
            </div>
            {outcome.stages.map((stage) => (
              <StageHeader key={stage.stageId} stage={stage} reached={reached.has(stage.stageId)} />
            ))}
          </div>

          {lanes.map((lane) => (
            <div className="chain-row" role="row" key={lane.id}>
              <div className="lane-label" role="rowheader">
                {lane.label}
              </div>
              {outcome.stages.map((stage) => (
                <div
                  className={`chain-cell ${stage.posture} ${reached.has(stage.stageId) ? '' : 'beyond-stop'}`}
                  role="cell"
                  key={`${lane.id}-${stage.stageId}`}
                >
                  <LaneCell lane={lane.id} stage={stage} sourceById={sourceById} />
                </div>
              ))}
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}

function StageHeader({ stage, reached }: { stage: StageOutcome; reached: boolean }) {
  return (
    <div className={`chain-cell chain-stage-header ${stage.posture} ${reached ? '' : 'beyond-stop'}`} role="columnheader">
      <div className="stage-head-row">
        <span className="stage-order">{stage.order}</span>
        <strong>{stage.stage.label}</strong>
      </div>
      <span className={`posture-badge ${stage.posture}`}>{postureLabels[stage.posture]}</span>
      <p className="stage-intent">{stage.stage.intent}</p>
      {stage.halted && (
        <span className={`stop-flag ${stage.stopKind}`}>
          {stage.stopKind === 'blocked' ? 'Attack blocked here' : 'Attack contained here'}
        </span>
      )}
      {!reached && <span className="stop-flag not-reached">Not reached in this model</span>}
    </div>
  );
}

function LaneCell({
  lane,
  stage,
  sourceById,
}: {
  lane: (typeof lanes)[number]['id'];
  stage: StageOutcome;
  sourceById: Map<LogSourceId, LogSource>;
}) {
  const { action, evidence, controls, gaps, remediation } = stage.scenarioStage;

  if (lane === 'action') {
    return (
      <>
        <strong className="cell-title">{action.summary}</strong>
        <p>{action.detail}</p>
        {action.technique && <span className="technique-tag">{action.technique}</span>}
      </>
    );
  }

  if (lane === 'evidence') {
    return evidence.length === 0 ? (
      <p className="empty-note">No evidence mapped.</p>
    ) : (
      <ul className="cell-list">
        {evidence.map((item) => (
          <li key={`${item.sourceId}-${item.signal}`}>
            <span className="cell-head evidence-head">
              <span className={`evidence-dot ${item.status}`} aria-hidden="true" />
              <strong>{sourceById.get(item.sourceId)?.name ?? item.sourceId}</strong>
            </span>
            <em>
              {item.signal} · {evidenceStatusLabels[item.status]}
            </em>
          </li>
        ))}
      </ul>
    );
  }

  if (lane === 'controls') {
    return controls.length === 0 ? (
      <p className="empty-note">No control mapped.</p>
    ) : (
      <ul className="cell-list">
        {controls.map((control) => (
          <li key={control.id}>
            <span className="cell-head">
              <span className={`effect-chip ${control.effect} ${control.outcome}`}>{controlEffectLabels[control.effect]}</span>
              <strong>{control.name}</strong>
            </span>
            <em>{control.note}</em>
          </li>
        ))}
      </ul>
    );
  }

  if (lane === 'gaps') {
    return gaps.length === 0 ? (
      <p className="empty-note">No open gap at this stage.</p>
    ) : (
      <ul className="cell-list">
        {gaps.map((gap) => (
          <li key={gap.id}>
            <span className="cell-head">
              <span className={`gap-chip ${gap.type}`}>{gapTypeLabels[gap.type]}</span>
              <strong>
                {gap.severity} severity · {gap.confidence} confidence
              </strong>
            </span>
            <em>{gap.statement}</em>
            <em className="gap-consequence">{gap.consequence}</em>
          </li>
        ))}
      </ul>
    );
  }

  return remediation.length === 0 ? (
    <p className="empty-note">Nothing queued.</p>
  ) : (
    <ul className="cell-list">
      {remediation.map((item) => (
        <li key={item.id}>
          <span className="cell-head">
            <span className={`effort-chip ${item.effort}`}>{item.effort} effort</span>
          </span>
          <strong>{item.action}</strong>
          <em>
            {item.owner} · target {item.targetDate}
          </em>
        </li>
      ))}
    </ul>
  );
}
