import { useMemo, useRef, useState, type ChangeEvent } from 'react';
import { ThreatModelPanel } from './components/ThreatModelPanel';
import { catalogue, type ThreatScenario, type LogSource, type LogSourceId } from './data/catalogue';
import { glossary } from './data/glossary';
import { sourceMetadata, type RemediationRecord } from './data/source-metadata';
import {
  buildSourceReadinessMap,
  buildVerificationDebt,
  buildVerificationStats,
  buildVerificationSummary,
  createInitialAssessmentState,
  getScenarioStatus,
  maturityLabels,
  type AssessmentMetadata,
  type AssessmentMode,
  type SourceAssessmentState,
  type SourceVerificationSummary,
  type VerificationDebtItem,
  type VerificationMaturity,
} from './lib/assessment';
import { buildExecutiveReport } from './lib/executive-report';
import { buildCoverageSummary, buildGapsCsv, formatPercent, type CoverageSummary, type VectorCoverage } from './lib/coverage';
import {
  buildSnapshotComparison,
  createSnapshot,
  loadSnapshots,
  parseSnapshot,
  saveSnapshot,
  serializeSnapshot,
  type AssessmentSnapshot,
} from './lib/snapshots';
import {
  buildRemediationStats,
  createInitialRemediationState,
  normalizeRemediationState,
  remediationGovernanceWarnings,
  type RemediationState,
} from './lib/remediation';
import './styles.css';

const primaryViews = [
  { id: 'Overview', label: 'Overview', hint: 'Assessment summary, metadata, and report framing.' },
  { id: 'Scope', label: 'Scope', hint: 'Confirm in-scope domains, handling boundaries, and context.' },
  { id: 'Verify', label: 'Source Readiness', hint: 'Verify critical evidence checks and maturity states.' },
  { id: 'Scenarios', label: 'Threat Modelling Scenarios', hint: 'Curated scenario-readiness review across threat-scenario flows.' },
  { id: 'Gaps', label: 'Gaps', hint: 'Prioritize remediation owners, dates, and open debt.' },
  { id: 'Report', label: 'Report', hint: 'Export, save, import, and compare in the report hub.' },
] as const;
type PrimaryView = (typeof primaryViews)[number]['id'];

const secondaryViews = [
  { id: 'Risk Matrix', label: 'Risk Matrix' },
  { id: 'Glossary', label: 'Glossary' },
  { id: 'Catalogue Notes', label: 'Catalogue Notes' },
] as const;
type SecondaryView = (typeof secondaryViews)[number]['id'];
type AppView = PrimaryView | SecondaryView;

function App() {
  const [activeView, setActiveView] = useState<AppView>('Overview');
  const [assessmentMode, setAssessmentMode] = useState<AssessmentMode>('demo');
  const [sourceState, setSourceState] = useState<Record<LogSourceId, SourceAssessmentState>>(() => createInitialAssessmentState('demo'));
  const [remediationState, setRemediationState] = useState<RemediationState>(() => createInitialRemediationState());
  const [metadata, setMetadata] = useState<AssessmentMetadata>({
    name: 'FY26 gap analysis readiness review',
    owner: 'Security operations',
    notes: '',
    scope: 'Readiness visualization for confirmed evidence sources and investigative workflows.',
  });
  const [domainFilter, setDomainFilter] = useState('All domains');
  const [gapsOnly, setGapsOnly] = useState(false);
  const [query, setQuery] = useState('');
  const [glossaryQuery, setGlossaryQuery] = useState('');
  const [snapshots, setSnapshots] = useState<AssessmentSnapshot[]>(() => loadSnapshots(window.localStorage));
  const [selectedSnapshotId, setSelectedSnapshotId] = useState('');
  const importRef = useRef<HTMLInputElement>(null);

  const sourceById = useMemo(() => new Map(catalogue.logSources.map((source) => [source.id, source])), []);
  const verificationSummary = useMemo(
    () => buildVerificationSummary(catalogue.logSources, sourceState),
    [sourceState],
  );
  const sourceReadiness = useMemo(() => buildSourceReadinessMap(verificationSummary), [verificationSummary]);
  const summary = useMemo(() => buildCoverageSummary(catalogue.riskVectors, sourceReadiness), [sourceReadiness]);
  const verificationStats = useMemo(() => buildVerificationStats(verificationSummary), [verificationSummary]);
  const verificationDebt = useMemo(
    () => buildVerificationDebt(catalogue.logSources, summary, verificationSummary),
    [summary, verificationSummary],
  );
  const executiveReport = useMemo(
    () =>
      buildExecutiveReport({
        mode: assessmentMode,
        metadata,
        summary,
        verificationSummary,
        scenarios: catalogue.threatScenarios,
        sources: catalogue.logSources,
        sourceMetadata,
        remediationState,
        catalogueVersion: catalogue.version,
      }),
    [assessmentMode, metadata, remediationState, summary, verificationSummary],
  );
  const domains = useMemo(() => ['All domains', ...new Set(catalogue.riskVectors.map((vector) => vector.domain))], []);
  const filteredVectors = useMemo(
    () =>
      summary.vectors.filter((item) => {
        const haystack = `${item.vector.domain} ${item.vector.name} ${item.vector.description} ${item.vector.investigationQuestions
          .map((question) => question.question)
          .join(' ')}`.toLowerCase();
        return (
          (domainFilter === 'All domains' || item.vector.domain === domainFilter) &&
          (!gapsOnly || item.score < 0.8) &&
          (query.trim() === '' || haystack.includes(query.toLowerCase()))
        );
      }),
    [domainFilter, gapsOnly, query, summary.vectors],
  );
  const selectedSnapshot = snapshots.find((snapshot) => snapshot.id === selectedSnapshotId);
  const activePrimaryIndex = primaryViews.findIndex((view) => view.id === activeView);
  const activePrimary = activePrimaryIndex >= 0 ? primaryViews[activePrimaryIndex] : null;
  const scenarioStatuses = useMemo(
    () => catalogue.threatScenarios.map((scenario) => ({ scenario, status: getScenarioStatus(scenario, verificationSummary) })),
    [verificationSummary],
  );
  const stoppedScenarioCount = scenarioStatuses.filter((item) => item.status.status === 'stopped').length;
  const topRemediation = summary.topMissingSources[0]
    ? {
        source: sourceById.get(summary.topMissingSources[0].sourceId),
        remediation: remediationState[summary.topMissingSources[0].sourceId],
        count: summary.topMissingSources[0].count,
      }
    : null;
  const snapshotComparison = useMemo(() => {
    if (!selectedSnapshot) return null;
    const baselineVerification = buildVerificationSummary(catalogue.logSources, selectedSnapshot.sourceState);
    const baselineReadiness = buildSourceReadinessMap(baselineVerification);
    const baselineSummary = buildCoverageSummary(catalogue.riskVectors, baselineReadiness);

    return buildSnapshotComparison(
      {
        overallScore: summary.overallScore,
        highRiskGapCount: summary.highRiskGapCount,
        readySourceCount: [...verificationSummary.values()].filter((item) => item.effective).length,
        evidenceCheckCount: countVerifiedChecks(sourceState),
      },
      {
        overallScore: baselineSummary.overallScore,
        highRiskGapCount: baselineSummary.highRiskGapCount,
        readySourceCount: [...baselineVerification.values()].filter((item) => item.effective).length,
        evidenceCheckCount: countVerifiedChecks(selectedSnapshot.sourceState),
      },
    );
  }, [selectedSnapshot, sourceState, summary, verificationSummary]);

  function updateMetadata<K extends keyof AssessmentMetadata>(key: K, value: AssessmentMetadata[K]) {
    setMetadata((current) => ({ ...current, [key]: value }));
  }

  function setMode(nextMode: AssessmentMode) {
    if (nextMode === assessmentMode) return;
    // Switching mode reseeds evidence and discards current verification work. Guard against
    // silently destroying an in-progress assessment (there is no autosave).
    const hasWork = countVerifiedChecks(sourceState) > 0;
    if (hasWork && !window.confirm(`Switching to ${nextMode === 'demo' ? 'Demo' : 'Real'} mode clears the current evidence and reseeds the worksheet. Save a snapshot first if you need it. Continue?`)) {
      return;
    }
    setAssessmentMode(nextMode);
    setSourceState(createInitialAssessmentState(nextMode));
  }

  function updateSourceMaturity(sourceId: LogSourceId, maturity: VerificationMaturity) {
    setSourceState((current) => ({
      ...current,
      [sourceId]: {
        ...current[sourceId],
        maturity,
      },
    }));
    setRemediationState((current) => ({
      ...current,
      [sourceId]: {
        ...current[sourceId],
        status:
          maturity === 'accepted-risk'
            ? 'accepted-risk'
            : current[sourceId].status === 'accepted-risk'
              ? 'not-started'
              : current[sourceId].status,
      },
    }));
  }

  function updateRemediation<K extends keyof RemediationRecord>(
    sourceId: LogSourceId,
    field: K,
    value: RemediationRecord[K],
  ) {
    setRemediationState((current) => ({
      ...current,
      [sourceId]: { ...current[sourceId], [field]: value },
    }));
    if (field === 'status') {
      setSourceState((current) => ({
        ...current,
        [sourceId]: {
          ...current[sourceId],
          maturity:
            value === 'accepted-risk'
              ? 'accepted-risk'
              : current[sourceId].maturity === 'accepted-risk'
                ? 'not-collected'
                : current[sourceId].maturity,
        },
      }));
    }
  }

  function toggleCheck(sourceId: LogSourceId, checkId: string) {
    setSourceState((current) => {
      const state = current[sourceId];
      const nextChecks = state.verifiedCheckIds.includes(checkId)
        ? state.verifiedCheckIds.filter((item) => item !== checkId)
        : [...state.verifiedCheckIds, checkId];
      return {
        ...current,
        [sourceId]: {
          ...state,
          verifiedCheckIds: nextChecks,
        },
      };
    });
  }

  function updateSourceEvidence(
    sourceId: LogSourceId,
    field: 'evidenceReference' | 'validatedBy' | 'validatedAt',
    value: string,
  ) {
    setSourceState((current) => ({
      ...current,
      [sourceId]: { ...current[sourceId], [field]: value },
    }));
  }

  function applyPreset(mode: 'all' | 'baseline' | 'clear') {
    if (mode === 'clear') {
      setSourceState(createInitialAssessmentState('real'));
      return;
    }

    if (mode === 'baseline') {
      setSourceState(createInitialAssessmentState('demo'));
      return;
    }

    setSourceState(
      Object.fromEntries(
        catalogue.logSources.map((source) => [
          source.id,
          {
            maturity: 'investigation-ready',
            verifiedCheckIds: source.verificationChecks.filter((check) => check.priority !== 'optional').map((check) => check.id),
            evidenceReference: 'Synthetic walkthrough evidence',
            validatedBy: 'Demo seed',
            validatedAt: '2026-01-01',
          },
        ]),
      ) as Record<LogSourceId, SourceAssessmentState>,
    );
  }

  function setSourceShortcut(source: LogSource, state: 'ready' | 'clear') {
    setSourceState((current) => ({
      ...current,
      [source.id]: {
        maturity: state === 'ready' ? 'investigation-ready' : 'not-collected',
        verifiedCheckIds:
          state === 'ready' ? source.verificationChecks.filter((check) => check.priority === 'critical').map((check) => check.id) : [],
        evidenceReference: state === 'ready' ? 'Synthetic walkthrough evidence' : '',
        validatedBy: state === 'ready' ? 'Demo seed' : '',
        validatedAt: state === 'ready' ? '2026-01-01' : '',
      },
    }));
  }

  function exportGapsCsv() {
    downloadFile(
      `threat-scenario-gaps-${todayStamp()}.csv`,
      buildGapsCsv(summary, catalogue.logSources, {
        assessmentMode,
        assessmentName: metadata.name,
        assessmentOwner: metadata.owner,
        catalogueVersion: catalogue.version,
        sourceMetadata,
        remediationState,
      }),
      'text/csv;charset=utf-8',
    );
  }

  function exportExecutiveMarkdown() {
    downloadFile(`threat-scenario-report-summary-${todayStamp()}.md`, executiveReport.markdown, 'text/markdown;charset=utf-8');
  }

  function exportSnapshotJson() {
    downloadFile(
      `threat-scenario-snapshot-${todayStamp()}.json`,
      serializeSnapshot(
        createSnapshot({
          catalogueVersion: catalogue.version,
          mode: assessmentMode,
          metadata,
          sourceState,
          remediationState,
        }),
      ),
      'application/json;charset=utf-8',
    );
  }

  function saveCurrentSnapshot() {
    const snapshot = createSnapshot({
      catalogueVersion: catalogue.version,
      mode: assessmentMode,
      metadata,
      sourceState,
      remediationState,
    });
    const next = saveSnapshot(window.localStorage, snapshot);
    setSnapshots(next);
    setSelectedSnapshotId(snapshot.id);
  }

  function handleImportSnapshot(event: ChangeEvent<HTMLInputElement>) {
    const file = event.target.files?.[0];
    if (!file) return;

    const reader = new FileReader();
    reader.onload = () => {
      const text = typeof reader.result === 'string' ? reader.result : '';
      const imported = parseSnapshot(text);
      setAssessmentMode(imported.mode);
      setMetadata(imported.metadata);
      setSourceState(imported.sourceState);
      setRemediationState(normalizeRemediationState(imported.remediationState));
      const next = saveSnapshot(window.localStorage, imported);
      setSnapshots(next);
      setSelectedSnapshotId(imported.id);
    };
    reader.readAsText(file);
    event.target.value = '';
  }

  return (
    <div className="app-shell">
      <header className="app-header">
        <div className="header-copy">
          <div className="eyebrow-row">
            <p className="eyebrow">Gaps Analysis Tool</p>
            <span className={`pill ${assessmentMode === 'real' ? 'warning-pill' : 'info-pill'}`}>
              {assessmentMode === 'real' ? 'Real mode: evidence starts blank' : 'Demo mode: seeded walkthrough'}
            </span>
          </div>
          <h1>Gaps Analysis Tool</h1>
          <p className="hero-copy">Desktop-first, white-first readiness review for SecOps, investigation, and evidence-readiness workshops.</p>
          <div className="button-row">
            <button className={assessmentMode === 'demo' ? 'active' : ''} onClick={() => setMode('demo')}>
              Demo mode
            </button>
            <button className={assessmentMode === 'real' ? 'active' : ''} onClick={() => setMode('real')}>
              Real assessment mode
            </button>
            <button className="primary-action" onClick={() => setActiveView('Report')}>
              Open report hub
            </button>
          </div>
        </div>
        <div className={`hero-score compact-score ${executiveReport.rag}`}>
          <span>{assessmentMode === 'demo' ? 'Seeded workshop readiness' : 'Current verified readiness'}</span>
          <strong>{formatPercent(summary.overallScore)}</strong>
          <small>{activePrimary ? `Step ${activePrimaryIndex + 1} of ${primaryViews.length}: ${activePrimary.label}` : 'Reference view open'}</small>
        </div>
      </header>

      <section className="summary-strip" aria-label="Shared assessment summary">
        <article className="summary-card">
          <span className="summary-label">Scope</span>
          <strong>{metadata.name}</strong>
          <p>{metadata.scope}</p>
          <small>{metadata.owner || 'Unassigned owner'}</small>
        </article>
        <article className="summary-card">
          <span className="summary-label">Source readiness</span>
          <strong>{formatPercent(summary.overallScore)}</strong>
          <p>{verificationStats.investigationReadySources} ready sources and {verificationStats.partialSources} partial sources</p>
          <small>{verificationStats.acceptedRiskSources} accepted risk</small>
        </article>
        <article className="summary-card">
          <span className="summary-label">Threat modelling status</span>
          <strong>
            {stoppedScenarioCount}/{catalogue.threatScenarios.length} covered
          </strong>
          <p>{scenarioStatuses.filter((item) => item.status.status !== 'stopped').length} scenarios still need stronger evidence coverage</p>
          <small>{summary.highRiskGapCount} high/critical gaps remain</small>
        </article>
        <article className="summary-card">
          <span className="summary-label">Top remediation action</span>
          <strong>{topRemediation ? topRemediation.source?.name ?? 'Tracked source' : 'No active remediation queue'}</strong>
          <p>
            {topRemediation
              ? `${topRemediation.remediation.recommendation}`
              : 'All tracked priority source gaps are currently resolved.'}
          </p>
          <small>
            {topRemediation
              ? `${topRemediation.remediation.gapOwner} · ${topRemediation.remediation.targetDate} · ${topRemediation.count} mapped vectors`
              : 'Review the report step for export and snapshot actions.'}
          </small>
        </article>
      </section>

      <section className="panel workflow-shell">
        <div className="panel-title-row compact">
          <div>
            <p className="eyebrow">Primary workflow</p>
            <h2>Work the assessment in order. Reference views stay off the main path.</h2>
          </div>
          <span className="pill info-pill">{activePrimary ? `Current step ${activePrimaryIndex + 1}/${primaryViews.length}` : 'Reference view'}</span>
        </div>
        <nav className="workflow-grid" aria-label="Primary workflow">
          {primaryViews.map((view) => (
            <button
              key={view.id}
              className={`workflow-button ${activeView === view.id ? 'active' : ''}`}
              aria-label={view.label}
              aria-pressed={activeView === view.id}
              onClick={() => setActiveView(view.id)}
            >
              <strong>{view.label}</strong>
              <small>{view.hint}</small>
            </button>
          ))}
        </nav>
      </section>

      <main className="main-stack">
        {activeView === 'Overview' && (
          <OverviewPanel
            metadata={metadata}
            updateMetadata={updateMetadata}
            summary={summary}
            report={executiveReport}
            verificationStats={verificationStats}
            verificationDebt={verificationDebt}
            scenarioStatuses={scenarioStatuses}
            onOpenScope={() => setActiveView('Scope')}
            onOpenReportHub={() => setActiveView('Report')}
          />
        )}

        {activeView === 'Scope' && (
          <ScopePanel
            assessmentMode={assessmentMode}
            metadata={metadata}
            summary={summary}
            verificationStats={verificationStats}
            sourceById={sourceById}
            verificationSummary={verificationSummary}
            remediationState={remediationState}
            onOpenVerify={() => setActiveView('Verify')}
          />
        )}

        {activeView === 'Verify' && (
          <VerificationWorkspace
            assessmentMode={assessmentMode}
            summary={summary}
            sourceState={sourceState}
            verificationSummary={verificationSummary}
            verificationDebt={verificationDebt}
            remediationState={remediationState}
            onPreset={applyPreset}
            onSourceMaturityChange={updateSourceMaturity}
            onToggleCheck={toggleCheck}
            onSourceEvidenceChange={updateSourceEvidence}
            onSourceShortcut={setSourceShortcut}
            onOpenNext={() => setActiveView('Scenarios')}
          />
        )}

        {activeView === 'Scenarios' && (
          <ThreatScenariosPanel
            summary={summary}
            verificationStats={verificationStats}
            verificationSummary={verificationSummary}
            verificationDebt={verificationDebt}
            sourceById={sourceById}
            onOpenGaps={() => setActiveView('Gaps')}
          />
        )}

        {activeView === 'Risk Matrix' && (
          <RiskMatrixPanel
            vectors={filteredVectors}
            domainFilter={domainFilter}
            domains={domains}
            gapsOnly={gapsOnly}
            query={query}
            sourceById={sourceById}
            onDomainChange={setDomainFilter}
            onGapsOnlyChange={setGapsOnly}
            onQueryChange={setQuery}
          />
        )}

        {activeView === 'Gaps' && (
          <GapAnalysisPanel
            summary={summary}
            onOpenReportHub={() => setActiveView('Report')}
            remediationState={remediationState}
            onRemediationChange={updateRemediation}
          />
        )}

        {activeView === 'Report' && (
          <ReportHubPanel
            metadata={metadata}
            report={executiveReport}
            snapshots={snapshots}
            selectedSnapshotId={selectedSnapshotId}
            selectedSnapshot={selectedSnapshot}
            comparison={snapshotComparison}
            onSave={saveCurrentSnapshot}
            onExportGapsCsv={exportGapsCsv}
            onExportMarkdown={exportExecutiveMarkdown}
            onExportSnapshot={exportSnapshotJson}
            onSelect={setSelectedSnapshotId}
            onImportClick={() => importRef.current?.click()}
          />
        )}

        {activeView === 'Glossary' && (
          <GlossaryPanel query={glossaryQuery} onQueryChange={setGlossaryQuery} />
        )}

        {activeView === 'Catalogue Notes' && <CatalogueNotes />}
      </main>

      <section className="panel secondary-shelf" aria-label="Reference views">
        <span className="shelf-label">Reference views</span>
        <div className="button-row">
          {secondaryViews.map((view) => (
            <button key={view.id} className={activeView === view.id ? 'active' : ''} aria-pressed={activeView === view.id} onClick={() => setActiveView(view.id)}>
              {view.label}
            </button>
          ))}
        </div>
      </section>

      <section className="panel trust-boundary">
        <div>
          <p className="eyebrow">Trust boundary</p>
          <p className="tight-copy">Readiness worksheet only: no event ingestion, replay, or automatic proof of wrongdoing.</p>
        </div>
        <details>
          <summary>Handling caveats</summary>
          <ul className="prose-list">
            <li>This app visualizes investigation readiness, gap priority, and scenario coverage from positively verified evidence.</li>
            <li>It does not replace SIEM, EDR, DLP, HR case-management, or analyst judgment.</li>
            <li>Email, HR/case, physical access, and behavioral context require minimum-necessary access, approval, and corroboration.</li>
          </ul>
        </details>
      </section>

      <input ref={importRef} type="file" accept="application/json" className="hidden-input" onChange={handleImportSnapshot} />
    </div>
  );
}

function OverviewPanel({
  metadata,
  updateMetadata,
  summary,
  report,
  verificationStats,
  verificationDebt,
  scenarioStatuses,
  onOpenScope,
  onOpenReportHub,
}: {
  metadata: AssessmentMetadata;
  updateMetadata: <K extends keyof AssessmentMetadata>(key: K, value: AssessmentMetadata[K]) => void;
  summary: CoverageSummary;
  report: ReturnType<typeof buildExecutiveReport>;
  verificationStats: ReturnType<typeof buildVerificationStats>;
  verificationDebt: VerificationDebtItem[];
  scenarioStatuses: Array<{ scenario: ThreatScenario; status: ReturnType<typeof getScenarioStatus> }>;
  onOpenScope: () => void;
  onOpenReportHub: () => void;
}) {
  return (
    <section className="grid two-col">
      <div className="panel">
        <div className="panel-title-row">
          <div>
            <p className="eyebrow">Overview</p>
            <h2>Assessment overview for workshop framing, verified readiness, and reporting</h2>
          </div>
          <div className="button-row">
            <button onClick={onOpenScope}>Open scope step</button>
            <button className="primary-action" onClick={onOpenReportHub}>
              Open report hub
            </button>
          </div>
        </div>
        <div className="form-grid">
          <label>
            Assessment name
            <input value={metadata.name} onChange={(event) => updateMetadata('name', event.target.value)} />
          </label>
          <label>
            Owner
            <input value={metadata.owner} onChange={(event) => updateMetadata('owner', event.target.value)} />
          </label>
          <label className="span-two">
            Scope statement
            <input value={metadata.scope} onChange={(event) => updateMetadata('scope', event.target.value)} />
          </label>
          <label className="span-two">
            Notes
            <textarea value={metadata.notes} onChange={(event) => updateMetadata('notes', event.target.value)} rows={3} />
          </label>
        </div>
        <div className="metric-grid">
          <Metric label="Overall readiness" value={formatPercent(summary.overallScore)} />
          <Metric label="High/critical gaps" value={summary.highRiskGapCount.toString()} />
          <Metric label="Ready sources" value={verificationStats.investigationReadySources.toString()} />
          <Metric label="Accepted risk" value={verificationStats.acceptedRiskSources.toString()} />
        </div>
        <p className="summary-callout">{report.plainEnglishSummary}</p>
        <div className="three-col dense-grid">
          <SummaryList title="Strengths" items={report.strengths} />
          <SummaryList title="Weaknesses" items={report.weaknesses} />
          <SummaryList title="Recommended investments" items={report.recommendedInvestments} />
        </div>
      </div>
      <div className="stack">
        <section className="panel">
          <p className="eyebrow">Top gaps</p>
          <h2>Largest verified readiness gaps</h2>
          <SummaryList title="" items={report.topGaps} />
        </section>
        <section className="panel">
          <p className="eyebrow">Threat modelling snapshot</p>
          <h2>Scenario readiness view</h2>
          <div className="compact-list">
            {scenarioStatuses.slice(0, 5).map(({ scenario, status }) => (
              <div className="list-card" key={scenario.id}>
                <strong>{scenario.title}</strong>
                <p>{status.label}</p>
                <small>{formatPercent(status.readinessScore)} readiness across curated control paths</small>
              </div>
            ))}
          </div>
        </section>
        <section className="panel verification-debt">
          <div className="panel-title-row compact">
            <h2>Open verification debt</h2>
            <span className="pill missing-pill">{verificationDebt.length} checks</span>
          </div>
          <div className="compact-list">
            {verificationDebt.slice(0, 5).map((item) => (
              <div className="list-card" key={`${item.sourceId}-${item.checkId}`}>
                <strong>{item.sourceName}</strong>
                <p>{item.checkLabel}</p>
                <small>{item.verificationQuestion}</small>
              </div>
            ))}
          </div>
        </section>
      </div>
    </section>
  );
}

function ScopePanel(props: {
  assessmentMode: AssessmentMode;
  metadata: AssessmentMetadata;
  summary: CoverageSummary;
  verificationStats: ReturnType<typeof buildVerificationStats>;
  sourceById: Map<LogSourceId, LogSource>;
  verificationSummary: ReturnType<typeof buildVerificationSummary>;
  remediationState: RemediationState;
  onOpenVerify: () => void;
}) {
  const readySources = [...props.verificationSummary.values()].filter((item) => item.effective).length;
  const prioritySources = summarySourceRows(props.verificationSummary, props.sourceById, props.remediationState);

  return (
    <section className="grid two-col">
      <section className="panel">
        <p className="eyebrow">Step 2</p>
        <h2>Confirm assessment scope and evidence-handling boundaries</h2>
        <p>Keep stakeholder framing in the shell and report, but preserve SecOps and investigation terminology in the working steps.</p>
        <div className="compact-list">
          <div className="list-card">
            <strong>Assessment</strong>
            <p>{props.metadata.name}</p>
            <small>{props.metadata.owner || 'No owner assigned yet'}</small>
          </div>
          <div className="list-card">
            <strong>Scope statement</strong>
            <p>{props.metadata.scope}</p>
            <small>{props.metadata.notes || 'No additional notes recorded.'}</small>
          </div>
        </div>
        <table className="data-table">
          <caption>Current in-scope source readiness rollup</caption>
          <thead>
            <tr>
              <th>Source</th>
              <th>Status</th>
              <th>Critical checks</th>
              <th>Gap owner</th>
            </tr>
          </thead>
          <tbody>
            {prioritySources.slice(0, 6).map((row) => (
              <tr key={row.sourceId}>
                <td>{row.sourceName}</td>
                <td>{row.status}</td>
                <td>
                  {row.criticalVerified}/{row.criticalTotal}
                </td>
                <td>{row.gapOwner}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </section>
      <section className="panel">
        <p className="eyebrow">Step 2 checkpoint</p>
        <h2>Move from scope into source readiness</h2>
        <div className="metric-grid compact-metrics">
          <Metric label="Coverage" value={formatPercent(props.summary.overallScore)} />
          <Metric label="Ready sources" value={readySources.toString()} />
          <Metric label="Accepted risk" value={props.verificationStats.acceptedRiskSources.toString()} />
          <Metric label="High/critical gaps" value={props.summary.highRiskGapCount.toString()} />
        </div>
        <ul className="prose-list">
          <li>Define which business areas and log domains are in scope.</li>
          <li>Confirm that HR, email, physical, or behavioral context is approval-gated and minimum-necessary.</li>
          <li>Use this assessment to visualize readiness gaps, not to substitute for actual SIEM/EDR/DLP investigations.</li>
        </ul>
        <div className="button-row">
          <button className="primary-action" onClick={props.onOpenVerify}>
            Open source readiness step
          </button>
          <span className={`pill ${props.assessmentMode === 'real' ? 'warning-pill' : 'info-pill'}`}>
            {props.assessmentMode === 'real' ? 'Real mode: no bulk verify shortcut' : 'Demo mode: seeded baseline'}
          </span>
        </div>
      </section>
    </section>
  );
}

function VerificationWorkspace({
  assessmentMode,
  summary,
  sourceState,
  verificationSummary,
  verificationDebt,
  remediationState,
  onPreset,
  onSourceMaturityChange,
  onToggleCheck,
  onSourceEvidenceChange,
  onSourceShortcut,
  onOpenNext,
}: {
  assessmentMode: AssessmentMode;
  summary: CoverageSummary;
  sourceState: Record<LogSourceId, SourceAssessmentState>;
  verificationSummary: ReturnType<typeof buildVerificationSummary>;
  verificationDebt: VerificationDebtItem[];
  remediationState: RemediationState;
  onPreset: (mode: 'all' | 'baseline' | 'clear') => void;
  onSourceMaturityChange: (sourceId: LogSourceId, maturity: VerificationMaturity) => void;
  onToggleCheck: (sourceId: LogSourceId, checkId: string) => void;
  onSourceEvidenceChange: (sourceId: LogSourceId, field: 'evidenceReference' | 'validatedBy' | 'validatedAt', value: string) => void;
  onSourceShortcut: (source: LogSource, state: 'ready' | 'clear') => void;
  onOpenNext?: () => void;
}) {
  const [needsAttentionOnly, setNeedsAttentionOnly] = useState(false);
  const attentionSources = useMemo(
    () =>
      catalogue.logSources.filter((source) => {
        const verification = verificationSummary.get(source.id);
        return verification ? sourceNeedsAttention(verification) : false;
      }),
    [verificationSummary],
  );
  const visibleSources = useMemo(
    () =>
      catalogue.logSources.filter((source) => {
        const verification = verificationSummary.get(source.id);
        if (!verification) return false;
        return !needsAttentionOnly || sourceNeedsAttention(verification);
      }),
    [needsAttentionOnly, verificationSummary],
  );

  return (
    <section className="stack">
      <div className="panel verification-console">
        <div className="panel-title-row">
          <div>
            <p className="eyebrow">Source Readiness</p>
            <h2>Verify readiness with explicit maturity states and critical evidence checks</h2>
            <p className="tight-copy">
              A source only closes critical scenario gaps when every critical check is verified and the source is investigation-ready. Accepted-risk stays visible as an unresolved evidence decision.
            </p>
          </div>
          <div className="button-row">
            {onOpenNext && (
              <button className="primary-action" onClick={onOpenNext}>
                Open threat modelling scenarios step
              </button>
            )}
            {assessmentMode === 'demo' && <button onClick={() => onPreset('all')}>Verify all demo checks</button>}
            <button onClick={() => onPreset('baseline')}>Load guided baseline</button>
            <button onClick={() => onPreset('clear')}>Clear evidence</button>
          </div>
        </div>
        <div className="panel-title-row compact progress-strip">
          <div className="source-progress-summary">
            <strong>Source progress</strong>
            <small>
              {verificationSummary.size - attentionSources.length}/{verificationSummary.size} sources do not need follow-up right now
            </small>
          </div>
          <div className="button-row">
            <label className="inline-check">
              <input type="checkbox" checked={needsAttentionOnly} onChange={(event) => setNeedsAttentionOnly(event.target.checked)} /> Needs attention only
            </label>
            <span className="pill missing-pill">{attentionSources.length} flagged</span>
          </div>
        </div>
        {assessmentMode === 'real' && (
          <p className="warning-copy">
            Real assessment mode removes the risky global verify-all shortcut. Set maturity and evidence one source at a time.
          </p>
        )}
      </div>

      <div className="source-detail-grid">
        {visibleSources.map((source) => {
          const verification = verificationSummary.get(source.id)!;
          const mappedVectors = summary.vectors.filter((vector) =>
            vector.vector.investigationQuestions.some((question) => question.evidence.some((evidence) => evidence.sourceId === source.id)),
          );
          const metadata = sourceMetadata[source.id];
          const remediation = remediationState[source.id];
          const isSensitive = ['email', 'hr-case', 'physical-access'].includes(source.id);
          const progressPercent = sourceProgressPercent(verification);
          const sourceStatus = describeSourceStatus(verification);

          return (
            <article className={`source-detail ${verification.effective ? 'selected' : ''} ${sourceNeedsAttention(verification) ? 'attention-card' : ''}`} key={source.id}>
              <div className="panel-title-row compact">
                <div>
                  <h3>{source.name}</h3>
                  <div className="tag-row">
                    <span className={`pill status-pill ${sourceStatus.tone}`} aria-label={`Source status ${sourceStatus.label}`}>
                      {sourceStatus.label}
                    </span>
                    {isSensitive && <span className="pill warning-pill">Sensitive handling</span>}
                    {sourceNeedsAttention(verification) && <span className="pill missing-pill">Needs attention</span>}
                  </div>
                </div>
                <span className="pill">{mappedVectors.length} vectors</span>
              </div>
              <p>{source.description}</p>
              <div className="progress-block" aria-label={`${source.name} progress`}>
                <div className="panel-title-row compact">
                  <small>Critical evidence progress</small>
                  <small>{progressPercent}%</small>
                </div>
                <progress max={100} value={progressPercent} />
              </div>
              <label>
                Maturity state
                <select value={sourceState[source.id].maturity} onChange={(event) => onSourceMaturityChange(source.id, event.target.value as VerificationMaturity)}>
                  {Object.entries(maturityLabels).map(([value, label]) => (
                    <option value={value} key={value}>
                      {label}
                    </option>
                  ))}
                </select>
              </label>
              <div className="source-stats">
                <span>Critical checks {verification.criticalVerified}/{verification.criticalTotal}</span>
                <span>Total checks {verification.verifiedChecks}/{verification.totalChecks}</span>
                <span>Evidence record {verification.evidenceRecorded ? 'complete' : 'missing'}</span>
                <span>Gap owner {remediation.gapOwner}</span>
              </div>
              {!verification.acceptedRisk && !verification.evidenceRecorded && (
                <p className="warning-copy">Record an evidence reference, validator, and validation date before this source can close coverage.</p>
              )}
              <details className="verification-detail">
                <summary>Evidence provenance</summary>
                <div className="form-grid remediation-form">
                  <label className="span-two">
                    Evidence reference
                    <input
                      value={sourceState[source.id].evidenceReference ?? ''}
                      onChange={(event) => onSourceEvidenceChange(source.id, 'evidenceReference', event.target.value)}
                      placeholder="Ticket, saved query, test run, dashboard, or evidence package reference"
                    />
                  </label>
                  <label>
                    Validated by
                    <input value={sourceState[source.id].validatedBy ?? ''} onChange={(event) => onSourceEvidenceChange(source.id, 'validatedBy', event.target.value)} />
                  </label>
                  <label>
                    Validation date
                    <input type="date" value={sourceState[source.id].validatedAt ?? ''} onChange={(event) => onSourceEvidenceChange(source.id, 'validatedAt', event.target.value)} />
                  </label>
                  <small className="span-two">Reference durable evidence; do not paste raw logs, private content, credentials, or unsafe samples.</small>
                </div>
              </details>
              <div className="tag-row">
                {metadata.glossaryTerms.map((term) => (
                  <span className="tag field" key={`${source.id}-${term}`}>
                    {term}
                  </span>
                ))}
              </div>
              <details className="verification-detail" open>
                <summary>Evidence checks</summary>
                <div className="check-list">
                  {source.verificationChecks.map((check) => (
                    <label className="check-row selectable" key={check.id}>
                      <div className="check-head">
                        <span>
                          <input
                            type="checkbox"
                            checked={sourceState[source.id].verifiedCheckIds.includes(check.id)}
                            onChange={() => onToggleCheck(source.id, check.id)}
                          />{' '}
                          <strong>{check.label}</strong>
                        </span>
                        <span className={`priority-badge ${check.priority}`}>{check.priority}</span>
                      </div>
                      <p>{check.verificationQuestion}</p>
                      <div className="tag-row">
                        {check.requiredFields.map((field) => (
                          <span className="tag field" key={`${check.id}-${field}`}>
                            {field}
                          </span>
                        ))}
                      </div>
                    </label>
                  ))}
                </div>
              </details>
              <details className="mapped-vector-detail">
                <summary>Privacy and remediation guidance</summary>
                <div className="compact-list">
                  {metadata.privacyNotes.map((note) => (
                    <div className="list-card" key={`${source.id}-${note}`}>
                      <small>{note}</small>
                    </div>
                  ))}
                  <div className="list-card">
                    <strong>{remediation.recommendation}</strong>
                    <small>
                      Owner: {remediation.gapOwner} · Engineering owner: {remediation.engineeringOwner} · Business owner: {remediation.businessOwner} · Due: {remediation.targetDate} · Status:{' '}
                      {remediation.status}
                    </small>
                  </div>
                </div>
              </details>
              {assessmentMode === 'demo' && (
                <div className="button-row compact-buttons">
                  <button onClick={() => onSourceShortcut(source, 'ready')}>Mark demo-ready</button>
                  <button onClick={() => onSourceShortcut(source, 'clear')}>Clear source</button>
                </div>
              )}
            </article>
          );
        })}
      </div>

      <section className="panel verification-debt">
        <div className="panel-title-row compact">
          <div>
            <p className="eyebrow">Verification debt</p>
            <h2>Verify these first before trusting the assessment</h2>
          </div>
          <span className="pill missing-pill">{verificationDebt.length} open checks</span>
        </div>
        <div className="debt-grid">
          {verificationDebt.slice(0, 8).map((item) => (
            <article className="debt-card" key={`${item.sourceId}-${item.checkId}`}>
              <div className="check-head">
                <strong>{item.sourceName}</strong>
                <span className={`priority-badge ${item.priority}`}>{item.priority}</span>
              </div>
              <h3>{item.checkLabel}</h3>
              <p>{item.verificationQuestion}</p>
              <p className="muted">
                Impacts {item.impactCount} vectors{item.impactedVectors.length > 0 ? `: ${item.impactedVectors.slice(0, 2).join(' · ')}` : ''}
              </p>
            </article>
          ))}
        </div>
      </section>
    </section>
  );
}

function ThreatScenariosPanel({
  summary,
  verificationStats,
  verificationSummary,
  verificationDebt,
  sourceById,
  onOpenGaps,
}: {
  summary: CoverageSummary;
  verificationStats: ReturnType<typeof buildVerificationStats>;
  verificationSummary: ReturnType<typeof buildVerificationSummary>;
  verificationDebt: VerificationDebtItem[];
  sourceById: Map<LogSourceId, LogSource>;
  onOpenGaps?: () => void;
}) {
  return (
    <section className="stack">
      <ThreatModelPanel sourceById={sourceById} />
      <div className="grid two-col">
        <div className="panel">
          <div className="panel-title-row">
            <div>
              <p className="eyebrow">Threat Modelling Scenarios</p>
              <h2>Curated scenario-readiness review across threat-scenario flows and investigative control paths</h2>
              <p className="tight-copy">This step reviews predefined scenario paths and evidence readiness. It does not implement free-form threat-model authoring.</p>
            </div>
            {onOpenGaps && (
              <button className="primary-action" onClick={onOpenGaps}>
                Open gaps step
              </button>
            )}
          </div>
          <div className="metric-grid compact-metrics">
            <Metric label="Ready sources" value={verificationStats.investigationReadySources.toString()} />
            <Metric label="Accepted risk" value={verificationStats.acceptedRiskSources.toString()} />
            <Metric label="Partial sources" value={verificationStats.partialSources.toString()} />
            <Metric label="Coverage" value={formatPercent(summary.overallScore)} />
          </div>
          <MiniFlow verificationSummary={verificationSummary} sourceById={sourceById} />
        </div>
        <section className="panel verification-debt">
          <p className="eyebrow">Highest verification debt</p>
          <h2>What still blocks clean scenario coverage</h2>
          <div className="compact-list">
            {verificationDebt.slice(0, 4).map((item) => (
              <div className="list-card" key={`${item.sourceId}-${item.checkId}`}>
                <strong>{item.sourceName}</strong>
                <p>{item.checkLabel}</p>
              </div>
            ))}
          </div>
        </section>
      </div>
      <div className="scenario-grid">
        {catalogue.threatScenarios.map((scenario) => (
          <ScenarioCard key={scenario.id} scenario={scenario} verificationSummary={verificationSummary} sourceById={sourceById} />
        ))}
      </div>
    </section>
  );
}

function ScenarioCard({
  scenario,
  verificationSummary,
  sourceById,
}: {
  scenario: ThreatScenario;
  verificationSummary: ReturnType<typeof buildVerificationSummary>;
  sourceById: Map<LogSourceId, LogSource>;
}) {
  const status = getScenarioStatus(scenario, verificationSummary);
  const flowSteps = catalogue.threatFlow.filter((step) => scenario.flowStepIds.includes(step.id));

  return (
    <article className={`scenario-card ${status.status}`}>
      <div className="panel-title-row compact">
        <h3>{scenario.title}</h3>
        <span className={`status scenario-status ${status.status}`}>
          {status.label}
        </span>
      </div>
      <p>{scenario.objective}</p>
      <div className="source-stats">
        <span>Scenario readiness {formatPercent(status.readinessScore)}</span>
        <span>Critical ready {status.criticalReady}/{scenario.criticalSources.length}</span>
        <span>Critical stopped {status.criticalEffective}/{scenario.criticalSources.length}</span>
      </div>
      <div className="scenario-flowline">
        {flowSteps.map((step) => {
          const stepStopped = step.controls.some((sourceId) => verificationSummary.get(sourceId)?.effective);
          return (
            <span className={`flow-chip ${stepStopped ? 'met' : 'missing'}`} key={step.id}>
              {stepStopped ? '✓' : '×'} {step.label}
            </span>
          );
        })}
      </div>
      <div className="control-objectives">
        <ControlList title="Critical controls" sourceIds={scenario.criticalSources} verificationSummary={verificationSummary} sourceById={sourceById} />
        <ControlList title="Recommended controls" sourceIds={scenario.recommendedSources} verificationSummary={verificationSummary} sourceById={sourceById} />
      </div>
    </article>
  );
}

function ControlList({
  title,
  sourceIds,
  verificationSummary,
  sourceById,
}: {
  title: string;
  sourceIds: LogSourceId[];
  verificationSummary: ReturnType<typeof buildVerificationSummary>;
  sourceById: Map<LogSourceId, LogSource>;
}) {
  return (
    <div>
      <strong>{title}</strong>
      <div className="tag-row">
        {sourceIds.map((sourceId) => {
          const item = verificationSummary.get(sourceId);
          const status = item ? describeSourceStatus(item) : { label: 'Unknown', tone: 'info-pill' };
          const ready = item?.effective;
          return (
            <span className={`tag ${ready ? 'covered' : 'missing'}`} key={`${title}-${sourceId}`}>
              {status.label}: {sourceById.get(sourceId)?.name ?? sourceId}
            </span>
          );
        })}
      </div>
    </div>
  );
}

function MiniFlow({
  verificationSummary,
  sourceById,
}: {
  verificationSummary: ReturnType<typeof buildVerificationSummary>;
  sourceById: Map<LogSourceId, LogSource>;
}) {
  return (
    <div className="mini-flow" aria-label="Internal scenario flow">
      {catalogue.threatFlow.map((step, index) => {
        const stopped = step.controls.some((sourceId) => verificationSummary.get(sourceId)?.effective);
        return (
          <div className={`mini-flow-node ${stopped ? 'stopped' : 'open'}`} key={step.id} style={{ animationDelay: `${index * 0.12}s` }}>
            <span>{index + 1}</span>
            <strong>{step.label}</strong>
            <small>{stopped ? 'Ready' : 'Gap'}</small>
            <div className="tag-row">
              {step.controls.slice(0, 2).map((sourceId) => (
                <em className={verificationSummary.get(sourceId)?.effective ? 'mini-control met' : 'mini-control missing'} key={`${step.id}-${sourceId}`}>
                  {sourceById.get(sourceId)?.name ?? sourceId}
                </em>
              ))}
            </div>
          </div>
        );
      })}
    </div>
  );
}

function RiskMatrixPanel({
  vectors,
  domains,
  domainFilter,
  gapsOnly,
  query,
  sourceById,
  onDomainChange,
  onGapsOnlyChange,
  onQueryChange,
}: {
  vectors: VectorCoverage[];
  domains: string[];
  domainFilter: string;
  gapsOnly: boolean;
  query: string;
  sourceById: Map<LogSourceId, LogSource>;
  onDomainChange: (value: string) => void;
  onGapsOnlyChange: (value: boolean) => void;
  onQueryChange: (value: string) => void;
}) {
  return (
    <section className="panel">
      <div className="panel-title-row">
        <div>
          <p className="eyebrow">Risk Matrix</p>
          <h2>Vectors, evidence questions, and maturity-weighted readiness</h2>
        </div>
        <div className="filters">
          <input value={query} onChange={(event) => onQueryChange(event.target.value)} placeholder="Search vectors or questions" />
          <select value={domainFilter} onChange={(event) => onDomainChange(event.target.value)}>
            {domains.map((domain) => (
              <option key={domain}>{domain}</option>
            ))}
          </select>
          <label className="inline-check">
            <input type="checkbox" checked={gapsOnly} onChange={(event) => onGapsOnlyChange(event.target.checked)} /> Gaps only
          </label>
        </div>
      </div>
      <div className="vector-list">
        {vectors.map((item) => (
          <article className={`vector-card ${item.status}`} key={item.vector.id}>
            <div className="vector-header">
              <div>
                <span className="pill">{item.vector.domain}</span>
                <span className={`pill severity ${item.vector.severity}`}>{item.vector.severity}</span>
                <h3>{item.vector.name}</h3>
                <p>{item.vector.description}</p>
              </div>
              <div className="score-block">
                <strong>{formatPercent(item.score)}</strong>
                <span>{item.status}</span>
              </div>
            </div>
            <p className="technique-note">{item.vector.techniqueAlignment}</p>
            <div className="question-list">
              {item.questions.map((question) => (
                <div className="question-row" key={question.questionId}>
                  <div>
                    <strong>{question.question}</strong>
                    <div className="tag-row">
                      {question.coveredSources.map((evidence) => (
                        <span className="tag covered" key={`${question.questionId}-${evidence.sourceId}`}>
                          Ready: {sourceById.get(evidence.sourceId)?.name ?? evidence.sourceId}
                        </span>
                      ))}
                      {[...question.missingPrimarySources, ...question.missingSupportingSources].map((evidence) => (
                        <span className="tag missing" key={`${question.questionId}-${evidence.sourceId}`}>
                          Missing: {sourceById.get(evidence.sourceId)?.name ?? evidence.sourceId}
                        </span>
                      ))}
                    </div>
                  </div>
                  <span className={`status ${question.status}`}>{formatPercent(question.score)}</span>
                </div>
              ))}
            </div>
          </article>
        ))}
      </div>
    </section>
  );
}

function GapAnalysisPanel({
  summary,
  onOpenReportHub,
  remediationState,
  onRemediationChange,
}: {
  summary: CoverageSummary;
  onOpenReportHub: () => void;
  remediationState: RemediationState;
  onRemediationChange: <K extends keyof RemediationRecord>(
    sourceId: LogSourceId,
    field: K,
    value: RemediationRecord[K],
  ) => void;
}) {
  const missingSources = summary.topMissingSources.slice(0, 8);
  const remediationStats = buildRemediationStats(
    remediationState,
    missingSources.map((item) => item.sourceId),
  );

  return (
    <section className="stack">
      <div className="panel">
        <div className="panel-title-row">
          <div>
            <p className="eyebrow">Gap Analysis</p>
            <h2>Prioritized remediation backlog with owners, dates, and privacy caveats</h2>
            <p className="tight-copy">Use the report hub for export and snapshot actions, then use the backlog cards below for follow-up planning.</p>
          </div>
          <button className="primary-action" onClick={onOpenReportHub}>
            Open report hub
          </button>
        </div>
        <div className="metric-grid compact-metrics">
          <Metric label="High/critical gaps" value={summary.highRiskGapCount.toString()} />
          <Metric label="Open actions" value={remediationStats.open.toString()} />
          <Metric label="Blocked / overdue" value={`${remediationStats.blocked} / ${remediationStats.overdue}`} />
          <Metric label="Governance warnings" value={(remediationStats.missingAccountability + remediationStats.missingValidationEvidence).toString()} />
        </div>
      </div>
      <div className="backlog-grid">
        {missingSources.map((item) => {
          const source = catalogue.logSources.find((entry) => entry.id === item.sourceId);
          const metadata = sourceMetadata[item.sourceId];
          const remediation = remediationState[item.sourceId];
          const governanceWarnings = remediationGovernanceWarnings(remediation);
          return (
            <article className="gap-card" key={item.sourceId}>
              <div className="panel-title-row compact">
                <h3>{source?.name ?? item.sourceId}</h3>
                <span className={`pill severity ${remediation.priority}`}>{remediation.priority}</span>
              </div>
              <p>{remediation.recommendation}</p>
              <div className="source-stats">
                <span>Accountable {remediation.gapOwner || 'Unassigned'}</span>
                <span>Engineering {remediation.engineeringOwner || 'Unassigned'}</span>
                <span>Business {remediation.businessOwner || 'Unassigned'}</span>
                <span>Target {remediation.targetDate || 'Not set'} ({remediation.slaDays}d SLA)</span>
                <span>Status {remediation.status}</span>
              </div>
              <p className="muted">
                Impacts {item.count} mapped vectors · weighted gap {item.weightedGap.toFixed(2)}
              </p>
              <div className="compact-list">
                {metadata.privacyNotes.map((note) => (
                  <div className="list-card" key={`${item.sourceId}-${note}`}>
                    <small>{note}</small>
                  </div>
                ))}
              </div>
              {governanceWarnings.length > 0 && (
                <div className="governance-warning" role="status">
                  <strong>Record needs attention</strong>
                  <ul className="prose-list">
                    {governanceWarnings.map((warning) => <li key={warning}>{warning}</li>)}
                  </ul>
                </div>
              )}
              <details className="remediation-editor">
                <summary>Update remediation record</summary>
                <div className="form-grid remediation-form">
                  <label>
                    Status
                    <select value={remediation.status} onChange={(event) => onRemediationChange(item.sourceId, 'status', event.target.value as RemediationRecord['status'])}>
                      {['not-started', 'planned', 'in-progress', 'blocked', 'accepted-risk', 'verified'].map((status) => <option key={status}>{status}</option>)}
                    </select>
                  </label>
                  <label>
                    Priority
                    <select value={remediation.priority} onChange={(event) => onRemediationChange(item.sourceId, 'priority', event.target.value as RemediationRecord['priority'])}>
                      {['critical', 'high', 'medium', 'low'].map((priority) => <option key={priority}>{priority}</option>)}
                    </select>
                  </label>
                  <label>Accountable owner<input value={remediation.gapOwner} onChange={(event) => onRemediationChange(item.sourceId, 'gapOwner', event.target.value)} /></label>
                  <label>Engineering owner<input value={remediation.engineeringOwner} onChange={(event) => onRemediationChange(item.sourceId, 'engineeringOwner', event.target.value)} /></label>
                  <label>Business owner<input value={remediation.businessOwner} onChange={(event) => onRemediationChange(item.sourceId, 'businessOwner', event.target.value)} /></label>
                  <label>Target date<input type="date" value={remediation.targetDate} onChange={(event) => onRemediationChange(item.sourceId, 'targetDate', event.target.value)} /></label>
                  <label>SLA days<input type="number" min={1} value={remediation.slaDays} onChange={(event) => onRemediationChange(item.sourceId, 'slaDays', Number(event.target.value))} /></label>
                  <label className="span-two">Recommendation<textarea rows={2} value={remediation.recommendation} onChange={(event) => onRemediationChange(item.sourceId, 'recommendation', event.target.value)} /></label>
                  <label className="span-two">Detection / use-case mapping<input value={remediation.detectionUseCase} onChange={(event) => onRemediationChange(item.sourceId, 'detectionUseCase', event.target.value)} /></label>
                  <label className="span-two">Validation method<textarea rows={2} value={remediation.validationMethod} onChange={(event) => onRemediationChange(item.sourceId, 'validationMethod', event.target.value)} /></label>
                  <label className="span-two">Evidence reference<input value={remediation.evidenceReference} onChange={(event) => onRemediationChange(item.sourceId, 'evidenceReference', event.target.value)} placeholder="Ticket, test run, query, dashboard, or evidence package reference" /></label>
                  {remediation.status === 'accepted-risk' && (
                    <>
                      <label className="span-two">Accepted-risk rationale<textarea rows={2} value={remediation.acceptedRiskRationale} onChange={(event) => onRemediationChange(item.sourceId, 'acceptedRiskRationale', event.target.value)} /></label>
                      <label>Risk review date<input type="date" value={remediation.riskReviewDate} onChange={(event) => onRemediationChange(item.sourceId, 'riskReviewDate', event.target.value)} /></label>
                    </>
                  )}
                  <label className="span-two">Working notes<textarea rows={2} value={remediation.notes} onChange={(event) => onRemediationChange(item.sourceId, 'notes', event.target.value)} /></label>
                </div>
              </details>
            </article>
          );
        })}
      </div>
    </section>
  );
}

function ReportHubPanel({
  metadata,
  report,
  snapshots,
  selectedSnapshotId,
  selectedSnapshot,
  comparison,
  onSave,
  onExportGapsCsv,
  onExportMarkdown,
  onExportSnapshot,
  onSelect,
  onImportClick,
}: {
  metadata: AssessmentMetadata;
  report: ReturnType<typeof buildExecutiveReport>;
  snapshots: AssessmentSnapshot[];
  selectedSnapshotId: string;
  selectedSnapshot?: AssessmentSnapshot;
  comparison: ReturnType<typeof buildSnapshotComparison> | null;
  onSave: () => void;
  onExportGapsCsv: () => void;
  onExportMarkdown: () => void;
  onExportSnapshot: () => void;
  onSelect: (id: string) => void;
  onImportClick: () => void;
}) {
  return (
    <section className="grid two-col">
      <div className="panel">
        <div className="panel-title-row">
          <div>
            <p className="eyebrow">Report Hub</p>
            <h2>Export reports, move snapshots, and compare saved assessments</h2>
          </div>
          <div className="button-row">
            <button className="primary-action" onClick={onExportMarkdown}>
              Export Markdown report
            </button>
            <button onClick={onExportGapsCsv}>Export gaps CSV</button>
            <button onClick={onExportSnapshot}>Export JSON snapshot</button>
          </div>
        </div>
        <p className="summary-callout">{report.plainEnglishSummary}</p>
        <div className="grid two-col hub-grid">
          <section className="mini-panel">
            <strong>Leadership report</strong>
            <p>Markdown executive summary with readiness, gaps, caveats, catalogue version, and generation timestamp.</p>
          </section>
          <section className="mini-panel">
            <strong>Working files</strong>
            <p>CSV gap register plus JSON snapshot export/import for local reuse, handoff, and regression comparison.</p>
          </section>
        </div>
      </div>
      <div className="stack">
        <section className="panel">
          <div className="panel-title-row">
            <div>
              <p className="eyebrow">Snapshots</p>
              <h2>Save, import, and compare point-in-time assessments</h2>
            </div>
            <div className="button-row">
              <button className="primary-action" onClick={onSave}>
                Save locally
              </button>
              <button onClick={onImportClick}>Import snapshot</button>
            </div>
          </div>
          <p className="tight-copy">
            Current assessment: <strong>{metadata.name}</strong>. Local snapshots stay in this browser unless you export them.
          </p>
          <div className="compact-list">
            {snapshots.length === 0 && <div className="list-card">No saved snapshots yet.</div>}
            {snapshots.map((snapshot) => (
              <button className={`snapshot-row ${selectedSnapshotId === snapshot.id ? 'active' : ''}`} key={snapshot.id} onClick={() => onSelect(snapshot.id)}>
                <strong>{snapshot.metadata.name}</strong>
                <small>
                  {snapshot.mode === 'demo' ? 'Demo' : 'Real'} · {formatDate(snapshot.createdAt)} · {snapshot.metadata.owner || 'No owner'}
                </small>
              </button>
            ))}
          </div>
        </section>
        <section className="panel">
          <p className="eyebrow">Comparison</p>
          <h2>Current vs selected snapshot</h2>
          {!selectedSnapshot && <p>Select a saved snapshot to compare.</p>}
          {selectedSnapshot && comparison && (
            <>
              <p className="tight-copy">
                Comparing against <strong>{selectedSnapshot.metadata.name}</strong> from {formatDate(selectedSnapshot.createdAt)}.
              </p>
              <div className="metric-grid compact-metrics">
                <Metric label="Coverage delta" value={signedPercent(comparison.scoreDelta)} />
                <Metric label="Gap delta" value={signedCount(comparison.highRiskGapDelta)} />
                <Metric label="Ready-source delta" value={signedCount(comparison.readySourceDelta)} />
                <Metric label="Evidence-check delta" value={signedCount(comparison.evidenceCheckDelta)} />
              </div>
            </>
          )}
        </section>
      </div>
    </section>
  );
}

function GlossaryPanel({
  query,
  onQueryChange,
}: {
  query: string;
  onQueryChange: (value: string) => void;
}) {
  const filtered = glossary.filter((item) => `${item.term} ${item.plainEnglish} ${item.whyItMatters}`.toLowerCase().includes(query.toLowerCase()));

  return (
    <section className="stack">
      <div className="panel">
        <div className="panel-title-row">
          <div>
            <p className="eyebrow">Glossary and help</p>
            <h2>Plain-English definitions for technical assessment terms</h2>
          </div>
          <input value={query} onChange={(event) => onQueryChange(event.target.value)} placeholder="Search terms" />
        </div>
      </div>
      <div className="help-grid">
        {filtered.map((item) => (
          <article className="mini-panel" key={item.term}>
            <h3>{item.term}</h3>
            <p>{item.plainEnglish}</p>
            <small>{item.whyItMatters}</small>
          </article>
        ))}
      </div>
    </section>
  );
}

function CatalogueNotes() {
  return (
    <section className="panel prose">
      <p className="eyebrow">Catalogue Notes</p>
      <h2>Catalogue integration status</h2>
      <ul className="prose-list">
        <li>Catalogue version: <strong>{catalogue.version}</strong></li>
        <li>{catalogue.summary}</li>
        <li>{catalogue.note}</li>
        <li>This product visualizes readiness gaps and verified evidence coverage. It does not ingest or replay raw events.</li>
        <li>HR, physical, email, and behavioral context remain corroborating inputs with privacy/legal handling constraints.</li>
      </ul>
    </section>
  );
}

function SummaryList({ title, items }: { title: string; items: string[] }) {
  return (
    <div className="summary-list">
      {title && <strong>{title}</strong>}
      <ul className="prose-list">
        {items.map((item, index) => (
          <li key={`${index}-${item}`}>{item}</li>
        ))}
      </ul>
    </div>
  );
}

function Metric({ label, value }: { label: string; value: string }) {
  return (
    <div className="metric">
      <span>{label}</span>
      <strong>{value}</strong>
    </div>
  );
}

function sourceNeedsAttention(verification: SourceVerificationSummary) {
  return !verification.effective && !verification.acceptedRisk;
}

function sourceProgressPercent(verification: SourceVerificationSummary) {
  if (verification.acceptedRisk) return 0;
  if (verification.criticalTotal === 0) return verification.effective ? 100 : Math.round(verification.readinessScore * 100);
  return Math.round((verification.criticalVerified / verification.criticalTotal) * 100);
}

function describeSourceStatus(verification: SourceVerificationSummary) {
  if (verification.effective) {
    return { label: 'Ready', tone: 'ready-pill' };
  }
  if (verification.acceptedRisk) {
    return { label: 'Accepted risk', tone: 'warning-pill' };
  }
  if (verification.readinessScore === 0) {
    return { label: 'High/critical gaps', tone: 'missing-pill' };
  }
  return { label: `Partial (${formatPercent(verification.readinessScore)} ready)`, tone: 'info-pill' };
}

function summarySourceRows(
  verificationSummary: ReturnType<typeof buildVerificationSummary>,
  sourceById: Map<LogSourceId, LogSource>,
  remediationState: RemediationState,
) {
  return [...verificationSummary.entries()]
    .map(([sourceId, verification]) => ({
      sourceId,
      sourceName: sourceById.get(sourceId)?.name ?? sourceId,
      status: describeSourceStatus(verification).label,
      criticalVerified: verification.criticalVerified,
      criticalTotal: verification.criticalTotal,
      gapOwner: remediationState[sourceId].gapOwner,
      sortScore: verification.effective ? 2 : verification.readinessScore > 0 ? 1 : 0,
    }))
    .sort((a, b) => a.sortScore - b.sortScore || a.sourceName.localeCompare(b.sourceName));
}

function downloadFile(filename: string, contents: string, type: string) {
  const blob = new Blob([contents], { type });
  const url = URL.createObjectURL(blob);
  const link = document.createElement('a');
  link.href = url;
  link.download = filename;
  document.body.append(link);
  link.click();
  link.remove();
  URL.revokeObjectURL(url);
}

function countVerifiedChecks(sourceState: Record<LogSourceId, SourceAssessmentState>) {
  return Object.values(sourceState).reduce((sum, item) => sum + item.verifiedCheckIds.length, 0);
}

function todayStamp() {
  return new Date().toISOString().slice(0, 10);
}

function formatDate(value: string) {
  return new Date(value).toISOString().slice(0, 10);
}

function signedPercent(value: number) {
  return `${value > 0 ? '+' : ''}${Math.round(value * 100)}%`;
}

function signedCount(value: number) {
  return `${value > 0 ? '+' : ''}${value}`;
}

export default App;
