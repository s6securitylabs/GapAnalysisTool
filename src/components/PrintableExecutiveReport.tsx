import { catalogue, type LogSourceId, type ThreatScenario } from '../data/catalogue';
import type { RemediationState } from '../lib/remediation';
import type { AssessmentMetadata, AssessmentMode, SourceVerificationSummary } from '../lib/assessment';
import type { ExecutiveReport } from '../lib/executive-report';
import { formatPercent, type CoverageSummary } from '../lib/coverage';

interface ScenarioStatusRow {
  scenario: ThreatScenario;
  status: {
    label: string;
    readinessScore: number;
  };
}

interface PrintableExecutiveReportProps {
  metadata: AssessmentMetadata;
  mode: AssessmentMode;
  summary: CoverageSummary;
  report: ExecutiveReport;
  verificationSummary: Map<LogSourceId, SourceVerificationSummary>;
  scenarioStatuses: ScenarioStatusRow[];
  remediationState: RemediationState;
  onClose: () => void;
  onPrint: () => void;
}

const severityOrder = { critical: 0, high: 1, medium: 2, low: 3 } as const;

export function PrintableExecutiveReport({
  metadata,
  mode,
  summary,
  report,
  verificationSummary,
  scenarioStatuses,
  remediationState,
  onClose,
  onPrint,
}: PrintableExecutiveReportProps) {
  const generatedAt = new Date();
  const sourceById = new Map(catalogue.logSources.map((source) => [source.id, source]));
  const openGaps = summary.vectors
    .filter((item) => item.score < 0.8)
    .sort((a, b) => severityOrder[a.vector.severity] - severityOrder[b.vector.severity] || b.riskGapScore - a.riskGapScore);
  const priorityGaps = openGaps.slice(0, 8);
  const priorityActions = summary.topMissingSources.slice(0, 6);
  const readySources = [...verificationSummary.values()].filter((item) => item.effective).length;
  const partialSources = [...verificationSummary.values()].filter((item) => !item.effective && item.readinessScore > 0 && !item.acceptedRisk).length;
  const acceptedRiskSources = [...verificationSummary.values()].filter((item) => item.acceptedRisk).length;
  const riskCounts = (['critical', 'high', 'medium', 'low'] as const).map((severity) => ({
    severity,
    count: openGaps.filter((item) => item.vector.severity === severity).length,
  }));
  const totalOpenRisk = Math.max(1, riskCounts.reduce((sum, item) => sum + item.count, 0));
  const weakestScenarios = [...scenarioStatuses].sort((a, b) => a.status.readinessScore - b.status.readinessScore).slice(0, 6);
  const circumference = 2 * Math.PI * 52;
  const readinessOffset = circumference * (1 - summary.overallScore);

  return (
    <main className="print-report-view">
      <div className="print-report-toolbar no-print" aria-label="Printable report actions">
        <button onClick={onClose}>Back to assessment</button>
        <button className="primary-action" onClick={onPrint}>Print or save PDF</button>
      </div>

      <article className="executive-report" aria-label="Printable executive report">
        {mode === 'demo' && <div className="demo-report-banner" role="note">Demo — synthetic data</div>}
        <header className="report-cover report-page">
          <div className="report-brand-row">
            <div className="report-brand"><img src={`${import.meta.env.BASE_URL}s6-security-labs-logo.svg`} alt="S6 Security Labs" /><div><strong>Gaps Analysis Tool</strong><small>Evidence readiness assessment</small></div></div>
            <span className={`report-rag report-rag-${report.rag}`}>{report.rag.toUpperCase()}</span>
          </div>
          <div className="report-cover-grid">
            <div>
              <p className="report-kicker">Executive evidence-readiness report</p>
              <h1>{metadata.name || 'Untitled assessment'}</h1>
              <p className="report-deck">Executive view of investigation readiness, material evidence gaps, exposed attack paths, and remediation priorities.</p>
              <dl className="report-meta">
                <div><dt>Owner</dt><dd>{metadata.owner || 'Unassigned'}</dd></div>
                <div><dt>Scope</dt><dd>{metadata.scope || 'Not stated'}</dd></div>
                <div><dt>Assessment</dt><dd>{mode === 'demo' ? 'Demo — synthetic data' : 'Real assessment'}</dd></div>
                <div><dt>Generated</dt><dd>{generatedAt.toLocaleString()}</dd></div>
              </dl>
            </div>
            <div className="readiness-graphic" aria-label={`${formatPercent(summary.overallScore)} overall readiness`}>
              <svg viewBox="0 0 132 132" role="img" aria-label={`Overall readiness ${formatPercent(summary.overallScore)}`}>
                <circle className="readiness-track" cx="66" cy="66" r="52" />
                <circle className={`readiness-value ${report.rag}`} cx="66" cy="66" r="52" strokeDasharray={circumference} strokeDashoffset={readinessOffset} />
                <text x="66" y="61" textAnchor="middle" className="readiness-number">{formatPercent(summary.overallScore)}</text>
                <text x="66" y="79" textAnchor="middle" className="readiness-label">READINESS</text>
              </svg>
            </div>
          </div>
          <div className="report-headline-metrics">
            <ReportMetric label="High/critical gaps" value={summary.highRiskGapCount.toString()} tone="danger" />
            <ReportMetric label="Ready sources" value={readySources.toString()} tone="success" />
            <ReportMetric label="Partially ready" value={partialSources.toString()} tone="warning" />
            <ReportMetric label="Accepted risk" value={acceptedRiskSources.toString()} tone="neutral" />
          </div>
          <div className={`executive-verdict executive-verdict-${report.rag}`}>
            <strong>Executive assessment</strong>
            <p>{report.plainEnglishSummary}</p>
          </div>
        </header>

        <section className="report-section report-page-break-before">
          <div className="report-section-heading">
            <div><p className="report-kicker">Risk picture</p><h2>Where the organisation is exposed</h2></div>
            <p>Open gaps are investigation paths below 80% verified evidence readiness. Severity and remaining evidence shortfall determine priority.</p>
          </div>
          <div className="report-two-column">
            <section className="report-card">
              <h3>Open gaps by severity</h3>
              <div className="risk-distribution" role="img" aria-label="Open gaps by severity">
                {riskCounts.map((item) => item.count > 0 && (
                  <span key={item.severity} className={`risk-segment ${item.severity}`} style={{ width: `${(item.count / totalOpenRisk) * 100}%` }} />
                ))}
              </div>
              <div className="risk-legend">
                {riskCounts.map((item) => <span key={item.severity}><i className={item.severity} />{item.severity} <strong>{item.count}</strong></span>)}
              </div>
            </section>
            <section className="report-card">
              <h3>Readiness by domain</h3>
              <div className="report-bars">
                {[...summary.domains].sort((a, b) => a.score - b.score).map((domain) => (
                  <div className="report-bar-row" key={domain.domain}>
                    <span>{domain.domain}</span><div><i style={{ width: formatPercent(domain.score) }} /></div><strong>{formatPercent(domain.score)}</strong>
                  </div>
                ))}
              </div>
            </section>
          </div>
          <section className="report-card report-table-card">
            <div className="report-card-heading"><h3>Priority investigation gaps</h3><span>{openGaps.length} paths below target</span></div>
            <table className="report-table">
              <thead><tr><th>Risk and investigation path</th><th>Coverage</th><th>Evidence missing</th><th>Priority</th></tr></thead>
              <tbody>
                {priorityGaps.map((gap) => (
                  <tr key={gap.vector.id}>
                    <td><strong>{gap.vector.name}</strong><small>{gap.vector.domain}</small></td>
                    <td><strong>{formatPercent(gap.score)}</strong><div className="table-progress"><i style={{ width: formatPercent(gap.score) }} /></div></td>
                    <td>{gap.missingSources.slice(0, 3).map((id) => sourceById.get(id)?.name ?? id).join(', ') || 'Supporting evidence only'}</td>
                    <td><span className={`report-severity ${gap.vector.severity}`}>{gap.vector.severity}</span><small>Index {gap.riskGapScore.toFixed(1)}</small></td>
                  </tr>
                ))}
              </tbody>
            </table>
          </section>
        </section>

        <section className="report-section report-page-break-before">
          <div className="report-section-heading">
            <div><p className="report-kicker">Threat modelling</p><h2>Scenarios with the weakest evidence</h2></div>
            <p>These results reflect verified source readiness for each priority investigation path; they do not infer compromise or wrongdoing.</p>
          </div>
          <div className="scenario-risk-grid">
            {weakestScenarios.map(({ scenario, status }, index) => (
              <article className="scenario-risk-card" key={scenario.id}>
                <span className="scenario-rank">{String(index + 1).padStart(2, '0')}</span>
                <div><h3>{scenario.title}</h3><p>{scenario.objective}</p></div>
                <div className="scenario-score"><strong>{formatPercent(status.readinessScore)}</strong><span>{executiveScenarioLabel(status.readinessScore)}</span></div>
              </article>
            ))}
          </div>
          <div className="report-two-column report-findings">
            <section className="report-card"><h3>What is working</h3><ul>{report.strengths.map((item) => <li key={item}>{item}</li>)}</ul></section>
            <section className="report-card"><h3>Material concerns</h3><ul>{report.weaknesses.filter((item) => !item.includes('mode')).map((item) => <li key={item}>{item}</li>)}</ul></section>
          </div>
        </section>

        <section className="report-section report-page-break-before">
          <div className="report-section-heading">
            <div><p className="report-kicker">Action plan</p><h2>Priority evidence improvements</h2></div>
            <p>Actions are ranked by the number and severity of investigation paths they improve. Recommendations remain catalogue guidance until owners and delivery dates are recorded.</p>
          </div>
          <div className="priority-action-list">
            {priorityActions.map((item, index) => {
              const source = sourceById.get(item.sourceId);
              const action = remediationState[item.sourceId];
              return (
                <article className="priority-action" key={item.sourceId}>
                  <span className="action-number">{index + 1}</span>
                  <div className="action-copy"><h3>{source?.name ?? item.sourceId}</h3><p>{action.recommendation}</p><small>Improves {item.count} mapped paths · combined priority impact {item.weightedGap.toFixed(1)}</small></div>
                  <dl><div><dt>Owner</dt><dd>{action.gapOwner || 'Unassigned'}</dd></div><div><dt>Target</dt><dd>{action.targetDate || 'Not set'}</dd></div><div><dt>Status</dt><dd>{action.status}</dd></div></dl>
                </article>
              );
            })}
          </div>
          <footer className="report-footer">
            <div><strong>Decision note</strong><p>{metadata.notes || 'No additional decision note was recorded.'}</p></div>
            <div><strong>Evidence boundary</strong><p>This report measures evidence readiness. It does not ingest raw logs, prove malicious intent, or replace investigation and legal review.</p></div>
            <small>Gaps Analysis Tool by S6 · Assessment model {catalogue.version} · Generated {generatedAt.toISOString()}</small>
          </footer>
        </section>
      </article>
    </main>
  );
}

function ReportMetric({ label, value, tone }: { label: string; value: string; tone: 'danger' | 'success' | 'warning' | 'neutral' }) {
  return <div className={`report-metric ${tone}`}><span>{label}</span><strong>{value}</strong></div>;
}

function executiveScenarioLabel(score: number) {
  if (score >= 0.8) return 'Investigable';
  if (score >= 0.5) return 'Partially investigable';
  if (score > 0) return 'Limited evidence';
  return 'Evidence blind';
}
