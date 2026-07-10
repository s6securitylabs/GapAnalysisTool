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
  type ScenarioKind,
  type ThreatScenario,
} from '../data/threat-model';
import { buildScenarioOutcome, serializeScenario } from '../lib/threat-model';
import { AttackChainMap } from './AttackChainMap';
import { ThreatSimulation } from './ThreatSimulation';

/**
 * The Threat Model workspace: one canonical model, two renderers, one switch.
 *
 * The primary Attack Chain Map is the default and the authority. The 3D Threat Simulation is
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
  const [libraryOpen, setLibraryOpen] = useState(false);
  const [libraryKind, setLibraryKind] = useState<'all' | ScenarioKind>('all');
  const [libraryQuery, setLibraryQuery] = useState('');

  const scenario = useMemo(
    () => threatModel.scenarios.find((item) => item.id === scenarioId) ?? threatModel.scenarios[0],
    [scenarioId],
  );
  const outcome = useMemo(() => buildScenarioOutcome(scenario), [scenario]);
  const libraryScenarios = useMemo(() => {
    const query = libraryQuery.trim().toLowerCase();
    return threatModel.scenarios.filter((item) => {
      const matchesKind = libraryKind === 'all' || item.kind === libraryKind;
      const haystack = `${item.title} ${item.actor} ${item.objective} ${item.summary} ${item.themes.join(' ')} ${scenarioTechniques(item).join(' ')}`.toLowerCase();
      return matchesKind && (query === '' || haystack.includes(query));
    });
  }, [libraryKind, libraryQuery]);
  const insiderScenarioCount = threatModel.scenarios.filter((item) => item.kind === 'internal').length;

  return (
    <section className="panel threat-model-panel">
      <div className="panel-title-row compact">
        <div>
          <p className="eyebrow">Attack scenarios</p>
          <h2>Follow the attack. Check the evidence.</h2>
          <p className="tight-copy">
            Choose a scenario to see the actions, evidence, controls, gaps, and response work at each stage. {threatModel.safety}
          </p>
          <p className="model-boundary">These scenario maps show example evidence requirements. They do not score the current assessment; verified investigation coverage appears below.</p>
        </div>
        <div className="mode-switch" role="group" aria-label="Visualisation mode">
          <button className={mode === '2d' ? 'active' : ''} aria-pressed={mode === '2d'} onClick={() => setMode('2d')}>
            Primary view
          </button>
          <button className={mode === '3d' ? 'active' : ''} aria-pressed={mode === '3d'} onClick={() => setMode('3d')}>
            3D map <span className="alpha-badge">Alpha</span>
          </button>
        </div>
      </div>

      <div className="scenario-picker-shell">
        <label className="scenario-picker">
          <span>Threat scenario</span>
          <select value={scenario.id} onChange={(event) => setScenarioId(event.target.value)}>
            {threatModel.scenarios.map((item) => (
              <option key={item.id} value={item.id}>
                {item.kind === 'internal' ? 'Internal' : 'Cyber'} — {item.title}
              </option>
            ))}
          </select>
        </label>
        <div className="scenario-selection-summary" aria-live="polite">
          <span className={`kind-tag ${scenario.kind}`}>{scenario.kind === 'internal' ? 'Internal' : 'Cyber'}</span>
          <strong>{scenario.title}</strong>
          <small>{scenario.themes.map((theme) => theme.replaceAll('-', ' ')).join(' · ')}</small>
        </div>
        <span className="pill info-pill">{threatModel.scenarios.length} attack scenarios</span>
        <button onClick={() => setLibraryOpen((open) => !open)} aria-expanded={libraryOpen}>
          {libraryOpen ? 'Close scenario library' : 'Browse scenario library'}
        </button>
      </div>

      {libraryOpen && (
        <section className="scenario-library" role="region" aria-label="Attack scenario library">
          <div className="scenario-library-head">
            <div>
              <strong>Attack scenario library</strong>
              <p>{insiderScenarioCount} insider and workforce scenarios · {threatModel.scenarios.length - insiderScenarioCount} external cyber scenarios</p>
            </div>
            <div className="library-filters">
              <input
                aria-label="Search attack scenarios"
                value={libraryQuery}
                onChange={(event) => setLibraryQuery(event.target.value)}
                placeholder="Search scenarios or techniques"
              />
              <select aria-label="Scenario type" value={libraryKind} onChange={(event) => setLibraryKind(event.target.value as 'all' | ScenarioKind)}>
                <option value="all">All scenarios</option>
                <option value="internal">Insider and workforce</option>
                <option value="cyber">External cyber</option>
              </select>
            </div>
          </div>
          <p className="library-boundary"><strong>Indicative ATT&amp;CK references.</strong> Validate mappings against your environment; non-malicious insider events may have no ATT&amp;CK equivalent.</p>
          <div className="scenario-library-grid" role="radiogroup" aria-label="Choose an attack scenario">
            {libraryScenarios.map((item) => {
              const techniques = scenarioTechniques(item);
              return (
                <button
                  className={`scenario-library-card ${scenario.id === item.id ? 'active' : ''}`}
                  key={item.id}
                  onClick={() => {
                    setScenarioId(item.id);
                    setLibraryOpen(false);
                  }}
                  role="radio"
                  aria-checked={scenario.id === item.id}
                >
                  <span className={`kind-tag ${item.kind}`}>{item.kind === 'internal' ? 'Insider / workforce' : 'External cyber'}</span>
                  <strong>{item.title}</strong>
                  <small>{item.objective}</small>
                  <span className="technique-list">{techniques.length > 0 ? techniques.join(' · ') : 'No direct ATT&CK mapping'}</span>
                </button>
              );
            })}
          </div>
        </section>
      )}

      <div className="scenario-brief compact-brief">
        <div>
          <p>
            <strong>Objective.</strong> {scenario.objective}
          </p>
          <p>{scenario.summary}</p>
        </div>
        <div className="scenario-actions">
          <button onClick={() => downloadJson(`threat-model-${scenario.id}.json`, serializeScenario(scenario))}>
            Export JSON
          </button>
          <span className="pill info-pill">
            Example model: {outcome.coveredStages}/{outcome.inPathStages} stages show usable evidence · {outcome.acceptedRiskStages} accepted risk
          </span>
        </div>
      </div>

      {/* Keying the scene on the scenario resets clock, camera, and buffers on every switch. */}
      {mode === '2d' ? <AttackChainMap scenario={scenario} sourceById={sourceById} /> : <ThreatSimulation key={scenario.id} scenario={scenario} />}

      <details className="model-legend visual-legend">
        <summary>Gap and control taxonomy legend</summary>
        <div className="legend-panel-grid">
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
      </details>
    </section>
  );
}

function scenarioTechniques(scenario: ThreatScenario) {
  return [...new Set(scenario.stages.map((stage) => stage.action.technique).filter((item): item is string => Boolean(item)))];
}
