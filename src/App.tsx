import { useMemo, useRef, useState, type ChangeEvent, type KeyboardEvent } from 'react';
import { ThreatModelPanel } from './components/ThreatModelPanel';
import { PrintableExecutiveReport } from './components/PrintableExecutiveReport';
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
  createBlankRemediationState,
  createInitialRemediationState,
  normalizeRemediationState,
  remediationGovernanceWarnings,
  type RemediationState,
} from './lib/remediation';
import './styles.css';

const primaryViews = [
  { id: 'Overview', label: 'Overview', hint: 'Assessment details, current coverage, and top gaps.' },
  { id: 'Scope', label: 'Scope', hint: 'Confirm in-scope domains, handling boundaries, and context.' },
  { id: 'Verify', label: 'Source Readiness', hint: 'Verify critical evidence checks and maturity states.' },
  { id: 'Scenarios', label: 'Threat Modelling', hint: 'Test investigation coverage against realistic threat paths.' },
  { id: 'Gaps', label: 'Gaps', hint: 'Prioritize remediation owners, dates, and open debt.' },
  { id: 'Report', label: 'Report', hint: 'Review the executive report and export assessment data.' },
  { id: 'References', label: 'References', hint: 'Trace risk scores and look up assessment terms.' },
] as const;
type PrimaryView = (typeof primaryViews)[number]['id'];

const secondaryViews = [
  { id: 'Risk register', label: 'Risk register' },
  { id: 'Research basis', label: 'Research basis' },
  { id: 'Definitions', label: 'Definitions' },
] as const;
type SecondaryView = (typeof secondaryViews)[number]['id'];

const insiderThreatResearch = [
  {
    title: 'Insider Threat Knowledge Base',
    publisher: 'MITRE',
    href: 'https://insiderthreat.mitre.org/',
    contribution: 'Frames insider threat as observable actions, assets, vulnerabilities, and mitigations rather than a single employee score.',
  },
  {
    title: 'Insider Threat Mitigation Guide',
    publisher: 'CISA',
    href: 'https://www.cisa.gov/resources-tools/resources/insider-threat-mitigation-guide',
    contribution: 'Supports a prevention, detection, response, and multidisciplinary programme model across people, process, physical, and cyber evidence.',
  },
  {
    title: 'Common Sense Guide to Mitigating Insider Threats, Seventh Edition',
    publisher: 'Carnegie Mellon SEI',
    href: 'https://www.sei.cmu.edu/library/common-sense-guide-to-mitigating-insider-threats-seventh-edition/',
    contribution: 'Grounds workforce lifecycle controls, access reviews, reporting routes, monitoring governance, and coordinated response practices.',
  },
  {
    title: 'Understanding Insider Threat: A Framework for Characterising Attacks',
    publisher: 'Nurse et al., IEEE Security and Privacy Workshops (2014)',
    href: 'https://doi.org/10.1109/SPW.2014.38',
    contribution: 'Supports reconstructing actor, action, system, asset, and contextual factors as a timeline instead of relying on one indicator.',
  },
  {
    title: 'Automated Insider Threat Detection System Using User and Role-Based Profile Assessment',
    publisher: 'Legg et al., IEEE Systems Journal (2017)',
    href: 'https://doi.org/10.1109/JSYST.2015.2438442',
    contribution: 'Supports role-aware technical baselines and multi-event corroboration while leaving judgement to an accountable review process.',
  },
  {
    title: 'Combining Traditional Cyber Security Audit Data with Psychosocial Data',
    publisher: 'Greitzer & Frincke (2010)',
    href: 'https://doi.org/10.1007/978-1-4419-7133-3_5',
    contribution: 'Motivates multidisciplinary correlation, but also reinforces why psychosocial context must be governed, proportionate, explainable, and never treated as proof of intent.',
  },
] as const;

const workforceIndicatorGroups = [
  ['Lifecycle', 'Joiner, mover, notice, leave, termination, and contractor dates; capture the event and control deadline, not an unnecessary reason.'],
  ['Role and access context', 'Role, manager, team, location, privileged duties, approved access profile, conflicts, exceptions, and segregation-of-duties context.'],
  ['Control completion', 'Access recertification, session revocation, offboarding tasks, device return, sponsor confirmation, and exception approvals.'],
  ['Structured case context', 'Approved referral type, policy/training acknowledgement, formal conflict disclosure, case status, owner, approver, and retention class.'],
  ['Corroborating evidence', 'Identity, SaaS, DLP, endpoint, file, network, physical-access, ticket, and business-process evidence aligned on a timeline.'],
  ['Governance', 'Lawful purpose, minimum necessary fields, access audit, retention, correction/appeal, multidisciplinary review, and documented human decision.'],
] as const;

const defaultAssessmentMetadata: AssessmentMetadata = {
  name: 'Untitled assessment',
  owner: '',
  notes: '',
  scope: '',
};

const guideAssessmentMetadata: AssessmentMetadata = {
  name: 'Example evidence gap assessment',
  owner: 'Security operations',
  notes: 'Synthetic example data for Demo mode.',
  scope: 'Evidence available for priority security investigations.',
};

function App() {
  const [activeView, setActiveView] = useState<PrimaryView>('Overview');
  const [activeReferenceView, setActiveReferenceView] = useState<SecondaryView>('Risk register');
  const [showDemoDialog, setShowDemoDialog] = useState(false);
  const [assessmentMode, setAssessmentMode] = useState<AssessmentMode>('real');
  const [sourceState, setSourceState] = useState<Record<LogSourceId, SourceAssessmentState>>(() => createInitialAssessmentState('real'));
  const [remediationState, setRemediationState] = useState<RemediationState>(() => createBlankRemediationState());
  const [metadata, setMetadata] = useState<AssessmentMetadata>(defaultAssessmentMetadata);
  const [domainFilter, setDomainFilter] = useState('All domains');
  const [gapsOnly, setGapsOnly] = useState(false);
  const [query, setQuery] = useState('');
  const [glossaryQuery, setGlossaryQuery] = useState('');
  const [snapshots, setSnapshots] = useState<AssessmentSnapshot[]>(() => loadSnapshots(window.localStorage));
  const [selectedSnapshotId, setSelectedSnapshotId] = useState('');
  const [snapshotMigrationNotes, setSnapshotMigrationNotes] = useState<string[]>([]);
  const [showPrintableReport, setShowPrintableReport] = useState(false);
  const importRef = useRef<HTMLInputElement>(null);
  const preGuideState = useRef<{
    metadata: AssessmentMetadata;
    sourceState: Record<LogSourceId, SourceAssessmentState>;
    remediationState: RemediationState;
  } | null>(null);

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
  const scenarioStatuses = useMemo(
    () => catalogue.threatScenarios.map((scenario) => ({ scenario, status: getScenarioStatus(scenario, verificationSummary) })),
    [verificationSummary],
  );

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

  function handleWorkflowKeyDown(event: KeyboardEvent<HTMLOListElement>) {
    const nextIndex =
      event.key === 'ArrowRight' || event.key === 'ArrowDown'
        ? Math.min(activePrimaryIndex + 1, primaryViews.length - 1)
        : event.key === 'ArrowLeft' || event.key === 'ArrowUp'
          ? Math.max(activePrimaryIndex - 1, 0)
          : event.key === 'Home'
            ? 0
            : event.key === 'End'
              ? primaryViews.length - 1
              : -1;
    if (nextIndex < 0 || nextIndex === activePrimaryIndex) return;
    event.preventDefault();
    setActiveView(primaryViews[nextIndex].id);
    requestAnimationFrame(() => document.getElementById(`workflow-step-${nextIndex + 1}`)?.focus());
  }

  function setMode(nextMode: AssessmentMode) {
    if (nextMode === assessmentMode) return;

    if (nextMode === 'demo') {
      preGuideState.current = { metadata, sourceState, remediationState };
      setAssessmentMode('demo');
      setMetadata(guideAssessmentMetadata);
      setSourceState(createInitialAssessmentState('demo'));
      setRemediationState(createInitialRemediationState());
      return;
    }

    const restored = preGuideState.current;
    setAssessmentMode('real');
    setMetadata(restored?.metadata ?? defaultAssessmentMetadata);
    setSourceState(restored?.sourceState ?? createInitialAssessmentState('real'));
    setRemediationState(restored?.remediationState ?? createBlankRemediationState());
    preGuideState.current = null;
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

  function applyPreset(mode: 'all' | 'clear') {
    if (mode === 'clear') {
      setSourceState(createInitialAssessmentState('real'));
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
      setSnapshotMigrationNotes(imported.migrationNotes ?? []);
      preGuideState.current = null;
      const next = saveSnapshot(window.localStorage, imported);
      setSnapshots(next);
      setSelectedSnapshotId(imported.id);
    };
    reader.readAsText(file);
    event.target.value = '';
  }

  if (showPrintableReport) {
    return (
      <PrintableExecutiveReport
        metadata={metadata}
        mode={assessmentMode}
        summary={summary}
        report={executiveReport}
        verificationSummary={verificationSummary}
        scenarioStatuses={scenarioStatuses}
        remediationState={remediationState}
        onClose={() => setShowPrintableReport(false)}
        onPrint={() => window.print()}
      />
    );
  }

  return (
    <div className="app-shell">
      <header className="app-header">
        <a className="hub-link" href="/" aria-label="Security Engineering Hub">
          <img className="s6-logo" src={`${import.meta.env.BASE_URL}s6-security-labs-logo.svg`} alt="S6 Security Labs" />
          <span className="hub-label">Security Engineering Hub</span>
        </a>
        <div className="app-title">
          <span>Evidence readiness assessment</span>
          <h1>Gaps Analysis Tool <small>by S6</small></h1>
        </div>
        <button className={assessmentMode === 'demo' ? 'active' : ''} onClick={() => assessmentMode === 'demo' ? setMode('real') : setShowDemoDialog(true)}>
          {assessmentMode === 'demo' ? 'Exit demo' : 'Demo'}
        </button>
      </header>
      {assessmentMode === 'demo' && (
        <aside className="guide-notice" aria-label="Demo mode">
          <strong>Demo data is loaded.</strong>
          <span>Use it to explore the workflow. Exit demo to restore your real assessment exactly as you left it.</span>
        </aside>
      )}
      {snapshotMigrationNotes.length > 0 && (
        <aside className="guide-notice snapshot-migration-notice" aria-label="Snapshot migration">
          <strong>Snapshot upgraded to the current catalogue.</strong>
          <ul>
            {snapshotMigrationNotes.map((note) => <li key={note}>{note}</li>)}
          </ul>
          <button type="button" onClick={() => setSnapshotMigrationNotes([])}>Dismiss</button>
        </aside>
      )}
      {showDemoDialog && (
        <div className="modal-backdrop" onMouseDown={(event) => event.target === event.currentTarget && setShowDemoDialog(false)}>
          <section
            className="demo-dialog"
            role="dialog"
            aria-modal="true"
            aria-labelledby="demo-dialog-title"
            aria-describedby="demo-dialog-description"
            tabIndex={-1}
            onKeyDown={(event) => event.key === 'Escape' && setShowDemoDialog(false)}
          >
            <p className="eyebrow">Demonstration mode</p>
            <h2 id="demo-dialog-title">Explore the tool with example data</h2>
            <p id="demo-dialog-description">Demo loads synthetic evidence, assessment details, and remediation examples so you can follow each step and see how the report works.</p>
            <ul className="prose-list">
              <li>Your current assessment is saved in memory before demo data is shown.</li>
              <li>Changes made in demo stay isolated from your real assessment and exports.</li>
              <li>Choose <strong>Exit demo</strong> at any time to restore your work.</li>
            </ul>
            <div className="button-row demo-dialog-actions">
              <button autoFocus onClick={() => setShowDemoDialog(false)}>Cancel</button>
              <button className="primary-action" onClick={() => { setMode('demo'); setShowDemoDialog(false); }}>Show demo data</button>
            </div>
          </section>
        </div>
      )}


      <section className="panel workflow-shell">
        <div className="panel-title-row compact">
          <div>
            <p className="eyebrow">Assessment steps</p>
            <h2>Define the scope, verify the evidence, then review the gaps.</h2>
          </div>
          <span className="pill info-pill">{`Current step ${activePrimaryIndex + 1}/${primaryViews.length}`}</span>
        </div>
        <nav aria-label="Assessment steps">
          <ol className="workflow-grid" onKeyDown={handleWorkflowKeyDown}>
            {primaryViews.map((view, index) => {
              const state = index < activePrimaryIndex ? 'complete' : index === activePrimaryIndex ? 'current' : index === activePrimaryIndex + 1 ? 'next' : 'upcoming';
              return (
                <li className={`workflow-step ${state}`} key={view.id}>
                  <button
                    id={`workflow-step-${index + 1}`}
                    className={`workflow-button ${activeView === view.id ? 'active' : ''}`}
                    aria-label={`${view.label}, step ${index + 1} of ${primaryViews.length}, ${state}`}
                    aria-current={activeView === view.id ? 'step' : undefined}
                    onClick={() => setActiveView(view.id)}
                  >
                    <span className="workflow-step-head">
                      <span className="workflow-number" aria-hidden="true">{index < activePrimaryIndex ? '✓' : index + 1}</span>
                      <span className="workflow-state">{state === 'complete' ? 'Complete' : state === 'current' ? 'Current' : state === 'next' ? 'Next' : 'Upcoming'}</span>
                    </span>
                    <strong>{view.label}</strong>
                    <small>{view.hint}</small>
                  </button>
                </li>
              );
            })}
          </ol>
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
            report={executiveReport}
            snapshots={snapshots}
            selectedSnapshotId={selectedSnapshotId}
            selectedSnapshot={selectedSnapshot}
            comparison={snapshotComparison}
            onSave={saveCurrentSnapshot}
            onExportGapsCsv={exportGapsCsv}
            onExportMarkdown={exportExecutiveMarkdown}
            onExportSnapshot={exportSnapshotJson}
            onOpenPrintableReport={() => setShowPrintableReport(true)}
            onSelect={setSelectedSnapshotId}
            onImportClick={() => importRef.current?.click()}
          />
        )}

        {activeView === 'References' && (
          <section className="stack" aria-labelledby="references-heading">
            <section className="panel reference-hub">
              <div>
                <p className="eyebrow">Supporting detail</p>
                <h2 id="references-heading">Check how a result was reached</h2>
                <p className="tight-copy">Trace readiness scores back to evidence questions, or look up an assessment term. Nothing on this page changes the assessment.</p>
              </div>
              <div className="button-row" role="group" aria-label="Reference views">
                {secondaryViews.map((view) => (
                  <button key={view.id} className={activeReferenceView === view.id ? 'active' : ''} aria-pressed={activeReferenceView === view.id} onClick={() => setActiveReferenceView(view.id)}>
                    {view.label}
                  </button>
                ))}
              </div>
            </section>

            {activeReferenceView === 'Risk register' && (
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
            {activeReferenceView === 'Research basis' && <ResearchBasisPanel />}
            {activeReferenceView === 'Definitions' && <GlossaryPanel query={glossaryQuery} onQueryChange={setGlossaryQuery} />}
          </section>
        )}
      </main>

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
            <h2>Assessment details and current evidence coverage</h2>
          </div>
          <div className="button-row overview-actions">
            <button onClick={onOpenScope}>Open scope step</button>
            <button className="primary-action" onClick={onOpenReportHub}>
              Review report
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
          <Metric label="Material risk gaps" value={summary.highRiskGapCount.toString()} />
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
          <p className="eyebrow">Attack scenarios</p>
          <h2>Current scenario coverage</h2>
          <div className="compact-list">
            {scenarioStatuses.slice(0, 5).map(({ scenario, status }) => (
              <div className="list-card" key={scenario.id}>
                <strong>{scenario.title}</strong>
                <p>{status.label}</p>
                <small>{formatPercent(status.readinessScore)} of required evidence ready</small>
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
        <p>Record what is in scope, who owns the assessment, and who may handle sensitive evidence.</p>
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
          <Metric label="Material risk gaps" value={props.summary.highRiskGapCount.toString()} />
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
            {props.assessmentMode === 'real' ? 'Evidence starts blank' : 'Guide data loaded'}
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
  onPreset: (mode: 'all' | 'clear') => void;
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
            {assessmentMode === 'real' && <button onClick={() => onPreset('clear')}>Clear evidence</button>}
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
            Verify each source individually. Set its maturity and record the evidence checks you confirmed.
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
              <details className="mapped-vector-detail" open>
                <summary>Why this log source matters, impact, and handling guidance</summary>
                <div className="compact-list">
                  <div className="list-card impact-card positive-impact">
                    <strong>Why we want it</strong>
                    <small>{metadata.whyCollect}</small>
                  </div>
                  <div className="list-card impact-card positive-impact">
                    <strong>Positive impact</strong>
                    <small>{metadata.positiveImpact}</small>
                  </div>
                  <div className="list-card impact-card negative-impact">
                    <strong>Negative impact / caveat</strong>
                    <small>{metadata.negativeImpact}</small>
                  </div>
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
  const [showCoverageDetails, setShowCoverageDetails] = useState(false);

  return (
    <section className="stack">
      <ThreatModelPanel sourceById={sourceById} />
      <div className="grid two-col">
        <div className="panel">
          <div className="panel-title-row">
            <div>
              <p className="eyebrow">Assessment coverage</p>
              <h2>Evidence readiness for priority investigations</h2>
              <p className="tight-copy">These measures use the evidence verified in this assessment.</p>
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
      <button className="disclosure-button" onClick={() => setShowCoverageDetails((visible) => !visible)} aria-expanded={showCoverageDetails}>
        {showCoverageDetails ? 'Hide investigation coverage details' : 'Show investigation coverage details'}
      </button>
      {showCoverageDetails && (
        <div className="scenario-grid">
          {catalogue.threatScenarios.map((scenario) => (
            <ScenarioCard key={scenario.id} scenario={scenario} verificationSummary={verificationSummary} sourceById={sourceById} />
          ))}
        </div>
      )}
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
        <span>Critical evidence ready {status.criticalEffective}/{scenario.criticalSources.length}</span>
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
        const evidenceReady = step.controls.some((sourceId) => verificationSummary.get(sourceId)?.effective);
        return (
          <div className={`mini-flow-node ${evidenceReady ? 'evidence-ready' : 'open'}`} key={step.id} style={{ animationDelay: `${index * 0.12}s` }}>
            <span>{index + 1}</span>
            <strong>{step.label}</strong>
            <small>{evidenceReady ? 'Evidence ready' : 'Evidence gap'}</small>
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
          <p className="eyebrow">Risk register</p>
          <h2>Evidence behind each readiness score</h2>
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
  const priorityGaps = summary.vectors
    .filter((item) => item.score < 0.8)
    .sort((a, b) => b.riskGapScore - a.riskGapScore)
    .slice(0, 8);
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
            <h2>Prioritised investigation gaps and evidence improvements</h2>
            <p className="tight-copy">Risk gaps are investigation paths below 80% verified evidence readiness. Source actions show which evidence improvements close the most risk.</p>
          </div>
          <button className="primary-action" onClick={onOpenReportHub}>
            Review report
          </button>
        </div>
        <div className="metric-grid compact-metrics">
          <Metric label="Material risk gaps" value={summary.highRiskGapCount.toString()} />
          <Metric label="Open actions" value={remediationStats.open.toString()} />
          <Metric label="Blocked / overdue" value={`${remediationStats.blocked} / ${remediationStats.overdue}`} />
          <Metric label="Governance warnings" value={(remediationStats.missingAccountability + remediationStats.missingValidationEvidence).toString()} />
        </div>
      </div>
      <section className="panel">
        <div className="panel-title-row compact">
          <div><p className="eyebrow">Priority gaps</p><h2>Investigation paths with the greatest remaining risk</h2></div>
          <span className="pill missing-pill">{summary.vectors.filter((item) => item.score < 0.8).length} below target</span>
        </div>
        <div className="priority-gap-grid">
          {priorityGaps.map((gap, index) => (
            <article className="priority-gap-card" key={gap.vector.id}>
              <div className="priority-gap-rank">{String(index + 1).padStart(2, '0')}</div>
              <div className="priority-gap-copy">
                <div className="panel-title-row compact"><h3>{gap.vector.name}</h3><span className={`pill severity ${gap.vector.severity}`}>{gap.vector.severity}</span></div>
                <p>{gap.vector.domain} · {formatPercent(gap.score)} evidence readiness</p>
                <div className="gap-progress" aria-label={`${gap.vector.name} ${formatPercent(gap.score)} ready`}><i style={{ width: formatPercent(gap.score) }} /></div>
                <small>Missing: {gap.missingSources.slice(0, 3).map((sourceId) => catalogue.logSources.find((source) => source.id === sourceId)?.name ?? sourceId).join(', ') || 'supporting evidence'} · Priority index {gap.riskGapScore.toFixed(1)}</small>
              </div>
            </article>
          ))}
        </div>
      </section>
      <div className="panel-title-row compact source-actions-heading">
        <div><p className="eyebrow">Source actions</p><h2>Evidence improvements with the broadest impact</h2></div>
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
                Improves {item.count} mapped investigation paths · combined priority impact {item.weightedGap.toFixed(1)}
              </p>
              <div className="compact-list">
                <div className="list-card impact-card positive-impact">
                  <strong>Why we want it</strong>
                  <small>{metadata.whyCollect}</small>
                </div>
                <div className="list-card impact-card positive-impact">
                  <strong>Positive impact</strong>
                  <small>{metadata.positiveImpact}</small>
                </div>
                <div className="list-card impact-card negative-impact">
                  <strong>Negative impact / caveat</strong>
                  <small>{metadata.negativeImpact}</small>
                </div>
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
  report,
  snapshots,
  selectedSnapshotId,
  selectedSnapshot,
  comparison,
  onSave,
  onExportGapsCsv,
  onExportMarkdown,
  onExportSnapshot,
  onOpenPrintableReport,
  onSelect,
  onImportClick,
}: {
  report: ReturnType<typeof buildExecutiveReport>;
  snapshots: AssessmentSnapshot[];
  selectedSnapshotId: string;
  selectedSnapshot?: AssessmentSnapshot;
  comparison: ReturnType<typeof buildSnapshotComparison> | null;
  onSave: () => void;
  onExportGapsCsv: () => void;
  onExportMarkdown: () => void;
  onExportSnapshot: () => void;
  onOpenPrintableReport: () => void;
  onSelect: (id: string) => void;
  onImportClick: () => void;
}) {
  return (
    <section className="grid two-col">
      <div className="panel">
        <div className="panel-title-row">
          <div>
            <p className="eyebrow">Executive report</p>
            <h2>Review the assessment before sharing it</h2>
          </div>
          <button className="primary-action" onClick={onOpenPrintableReport}>Open executive report</button>
        </div>
        <p className="summary-callout">{report.plainEnglishSummary}</p>
        <div className="report-purpose">
          <strong>Before distribution</strong>
          <p>Confirm the assessment owner, scope, gap owners, and target dates. Unrecorded fields remain visibly unassigned in the report.</p>
        </div>
        <div className="report-export-group">
          <div>
            <strong>Supporting files</strong>
            <p>Use CSV for the remediation register, Markdown for editable narrative, or JSON to move the full assessment between browsers.</p>
          </div>
          <div className="button-row">
            <button onClick={onExportGapsCsv}>Export gaps CSV</button>
            <button onClick={onExportMarkdown}>Export Markdown</button>
            <button onClick={onExportSnapshot}>Export assessment JSON</button>
          </div>
        </div>
      </div>
      <div className="stack">
        <section className="panel">
          <div className="panel-title-row">
            <div>
              <p className="eyebrow">Optional progress tracking</p>
              <h2>Compare with an earlier assessment</h2>
            </div>
            <div className="button-row">
              <button className="primary-action" onClick={onSave}>Save locally</button>
              <button onClick={onImportClick}>Import snapshot</button>
            </div>
          </div>
          <p className="tight-copy">Save a dated copy before making changes. Browser snapshots stay on this device unless exported as JSON.</p>
          <div className="compact-list">
            {snapshots.length === 0 && <div className="list-card">No saved snapshots yet.</div>}
            {snapshots.map((snapshot) => (
              <button className={`snapshot-row ${selectedSnapshotId === snapshot.id ? 'active' : ''}`} key={snapshot.id} onClick={() => onSelect(snapshot.id)}>
                <strong>{snapshot.metadata.name}</strong>
                <small>{snapshot.mode === 'demo' ? 'Demo' : 'Real'} · {formatDate(snapshot.createdAt)} · {snapshot.metadata.owner || 'No owner'}</small>
              </button>
            ))}
          </div>
        </section>
        {selectedSnapshot && comparison && (
          <section className="panel">
            <p className="eyebrow">Change since snapshot</p>
            <h2>{selectedSnapshot.metadata.name}</h2>
            <p className="tight-copy">Saved {formatDate(selectedSnapshot.createdAt)}. Positive coverage and evidence-check deltas indicate improved readiness; fewer gaps is an improvement.</p>
            <div className="metric-grid compact-metrics">
              <Metric label="Coverage delta" value={signedPercent(comparison.scoreDelta)} />
              <Metric label="Gap delta" value={signedCount(comparison.highRiskGapDelta)} />
              <Metric label="Ready-source delta" value={signedCount(comparison.readySourceDelta)} />
              <Metric label="Evidence-check delta" value={signedCount(comparison.evidenceCheckDelta)} />
            </div>
          </section>
        )}
      </div>
    </section>
  );
}

function ResearchBasisPanel() {
  return (
    <div className="workspace-stack research-basis">
      <section className="panel">
        <div className="panel-title-row">
          <div>
            <p className="eyebrow">Insider-threat programme foundation</p>
            <h2>Research basis and indicator boundaries</h2>
            <p className="tight-copy">MITRE, CISA, SEI, and peer-reviewed research support combining workforce, organisational, technical, physical, and case evidence. They do not justify an opaque employee guilt score.</p>
          </div>
        </div>
        <div className="callout neutral">
          <strong>Assessment rule</strong>
          <p>Use workforce context to trigger proportionate human review. Require corroborating activity or control evidence before escalation, record competing explanations, and keep the final decision attributable to an authorised multidisciplinary team.</p>
        </div>
        <div className="research-grid" aria-label="Workforce and organisational indicator groups">
          {workforceIndicatorGroups.map(([title, description]) => (
            <article className="research-card" key={title}>
              <h3>{title}</h3>
              <p>{description}</p>
            </article>
          ))}
        </div>
      </section>

      <section className="panel">
        <div className="panel-title-row">
          <div>
            <p className="eyebrow">Sources reviewed</p>
            <h2>Primary guidance and scholarly research</h2>
            <p className="tight-copy">These references shape the catalogue and its safeguards. Local law, industrial instruments, employment agreements, and privacy review still control implementation.</p>
          </div>
        </div>
        <div className="research-source-list">
          {insiderThreatResearch.map((source) => (
            <article className="research-source" key={source.href}>
              <div>
                <h3><a href={source.href} target="_blank" rel="noreferrer">{source.title}</a></h3>
                <p className="muted">{source.publisher}</p>
              </div>
              <p>{source.contribution}</p>
            </article>
          ))}
        </div>
      </section>
    </div>
  );
}

function GlossaryPanel({
  query,
  onQueryChange,
}: {
  query: string;
  onQueryChange: (value: string) => void;
}) {
  const [category, setCategory] = useState('All');
  const categories = ['All', ...new Set(glossary.map((item) => item.category))];
  const normalizedQuery = query.trim().toLowerCase();
  const filtered = glossary
    .filter((item) => category === 'All' || item.category === category)
    .filter((item) => `${item.term} ${item.category} ${item.plainEnglish} ${item.whyItMatters}`.toLowerCase().includes(normalizedQuery))
    .sort((a, b) => a.term.localeCompare(b.term));

  return (
    <section className="stack">
      <div className="panel glossary-head">
        <div className="panel-title-row">
          <div>
            <p className="eyebrow">Glossary and help</p>
            <h2>Clear terms. Defensible decisions.</h2>
            <p>Know what would prevent the path, what would expose it, and what remains only a lead.</p>
          </div>
          <div className="glossary-tools">
            <input aria-label="Search glossary" value={query} onChange={(event) => onQueryChange(event.target.value)} placeholder="Search terms" />
            <select aria-label="Glossary category" value={category} onChange={(event) => setCategory(event.target.value)}>
              {categories.map((item) => <option key={item}>{item}</option>)}
            </select>
            <small>{filtered.length} of {glossary.length} terms</small>
          </div>
        </div>
      </div>
      {filtered.length > 0 ? (
        <div className="help-grid">
          {filtered.map((item) => (
            <article className="mini-panel glossary-card" key={item.term}>
              <span className="glossary-category">{item.category}</span>
              <h3>{item.term}</h3>
              <p>{item.plainEnglish}</p>
              <small>{item.whyItMatters}</small>
            </article>
          ))}
        </div>
      ) : (
        <div className="panel empty-state"><strong>No matching term.</strong><p>Try a broader search or select All categories.</p></div>
      )}
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
    return { label: 'No usable evidence', tone: 'missing-pill' };
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
