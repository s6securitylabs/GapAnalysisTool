import { useMemo, useState } from 'react';
import type { LogSource, LogSourceId } from '../data/catalogue';
import {
  controlEffectLabels,
  controlEffectMeanings,
  gapTypeLabels,
  gapTypeMeanings,
  threatModel,
  type ControlEffect,
  type GapType,
} from '../data/threat-model';
import { buildScenarioOutcome, serializeScenario } from '../lib/threat-model';
import { AttackChainMap } from './AttackChainMap';
import { ThreatSimulation } from './ThreatSimulation';

/**
 * The Threat Model workspace: one canonical model, two renderers, one switch.
 *
 * The 2D Attack Chain Map is the default and the authority. The 3D Threat Simulation is
 * progressive enhancement for workshops and exploration. Switching modes changes how the
 * model is drawn and never what it says.
 */

export type VisualisationMode = '2d' | '3d';

const gapTypes: GapType[] = ['telemetry', 'detection', 'response', 'accepted-risk'];
const controlEffects: ControlEffect[] = ['block', 'detect', 'delay', 'contain', 'investigate'];

function downloadJson(filename: string, contents: string) {
  const url = URL.createObjectURL(new Blob([contents], { type: 'application/json' }));
  const link = document.createElement('a');
  link.href = url;
  link.download = filename;
  link.click();
  URL.revokeObjectURL(url);
}

export function ThreatModelPanel({ sourceById }: { sourceById: Map<LogSourceId, LogSource> }) {
  const [scenarioId, setScenarioId] = useState(threatModel.scenarios[0].id);
  const [mode, setMode] = useState<VisualisationMode>('2d');

  const scenario = useMemo(
    () => threatModel.scenarios.find((item) => item.id === scenarioId) ?? threatModel.scenarios[0],
    [scenarioId],
  );
  const outcome = useMemo(() => buildScenarioOutcome(scenario), [scenario]);

  return (
    <section className="panel threat-model-panel">
      <div className="panel-title-row compact">
        <div>
          <p className="eyebrow">Threat Model</p>
          <h2>One threat model across the attack chain, drawn two ways</h2>
          <p className="tight-copy">
            The 2D Attack Chain Map is the authoritative view for review, print, and export. The 3D Threat Simulation renders the
            same model for exploration and workshop facilitation. {threatModel.safety}
          </p>
        </div>
        <div className="mode-switch" role="group" aria-label="Visualisation mode">
          <button className={mode === '2d' ? 'active' : ''} aria-pressed={mode === '2d'} onClick={() => setMode('2d')}>
            2D Attack Chain Map
          </button>
          <button className={mode === '3d' ? 'active' : ''} aria-pressed={mode === '3d'} onClick={() => setMode('3d')}>
            3D Threat Simulation
          </button>
        </div>
      </div>

      <div className="scenario-switch" role="group" aria-label="Threat scenario">
        {threatModel.scenarios.map((item) => (
          <button
            key={item.id}
            className={`scenario-chip ${item.kind} ${item.id === scenario.id ? 'active' : ''}`}
            aria-pressed={item.id === scenario.id}
            onClick={() => setScenarioId(item.id)}
          >
            <span className={`kind-tag ${item.kind}`}>{item.kind === 'internal' ? 'Internal' : 'Cyber'}</span>
            <strong>{item.title}</strong>
            <span className="scenario-themes">{item.themes.map((theme) => theme.replaceAll('-', ' ')).join(' · ')}</span>
          </button>
        ))}
      </div>

      <div className="scenario-brief">
        <p>
          <strong>Objective.</strong> {scenario.objective}
        </p>
        <p>{scenario.summary}</p>
        <p className="scenario-theme-line"><strong>Coverage themes.</strong> {scenario.themes.map((theme) => theme.replaceAll('-', ' ')).join(' · ')}</p>
        <div className="button-row">
          <button onClick={() => downloadJson(`threat-model-${scenario.id}.json`, serializeScenario(scenario))}>
            Export threat model (JSON)
          </button>
          <span className="pill info-pill">
            {outcome.coveredStages}/{outcome.inPathStages} in-path stages covered · {outcome.acceptedRiskStages} accepted risk contributes no coverage
          </span>
        </div>
      </div>

      {/* Keying the scene on the scenario resets clock, camera, and buffers on every switch. */}
      {mode === '2d' ? <AttackChainMap scenario={scenario} sourceById={sourceById} /> : <ThreatSimulation key={scenario.id} scenario={scenario} />}

      <div className="model-legend">
        <div>
          <strong>Gap types</strong>
          <ul>
            {gapTypes.map((type) => (
              <li key={type}>
                <span className={`gap-chip ${type}`}>{gapTypeLabels[type]}</span>
                <em>{gapTypeMeanings[type]}</em>
              </li>
            ))}
          </ul>
        </div>
        <div>
          <strong>What a control actually does</strong>
          <ul>
            {controlEffects.map((effect) => (
              <li key={effect}>
                <span className={`effect-chip ${effect} holds`}>{controlEffectLabels[effect]}</span>
                <em>{controlEffectMeanings[effect]}</em>
              </li>
            ))}
          </ul>
        </div>
      </div>
    </section>
  );
}
