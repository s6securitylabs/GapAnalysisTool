import { render, screen, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';

import App from './App';

beforeAll(() => {
  class ResizeObserverMock {
    observe() {}
    unobserve() {}
    disconnect() {}
  }

  Object.defineProperty(globalThis, 'ResizeObserver', {
    value: ResizeObserverMock,
    configurable: true,
  });

  Object.defineProperty(globalThis.URL, 'createObjectURL', {
    value: vi.fn(() => 'blob:test'),
    configurable: true,
  });

  Object.defineProperty(globalThis.URL, 'revokeObjectURL', {
    value: vi.fn(),
    configurable: true,
  });

  // Mode switching guards against data loss via window.confirm (unimplemented in jsdom).
  vi.spyOn(window, 'confirm').mockReturnValue(true);
});

beforeEach(() => {
  window.localStorage.clear();
});

async function enterDemoMode() {
  await userEvent.click(screen.getByRole('button', { name: /^Demo$/i }));
  expect(screen.getByRole('dialog', { name: /Explore the tool with example data/i })).toBeInTheDocument();
  await userEvent.click(screen.getByRole('button', { name: /Show demo data/i }));
}

describe('App integrated assessment experience', () => {
  it('defaults to overview with an ordered seven-step workflow and no repeated reference footer', () => {
    render(<App />);
    const workflowNav = screen.getByRole('navigation', { name: /Assessment steps/i });

    expect(screen.getByRole('heading', { name: /^Gaps Analysis Tool$/i })).toBeInTheDocument();
    expect(screen.getByRole('heading', { name: /Find the evidence gaps that would slow a serious investigation/i })).toBeInTheDocument();
    expect(screen.getByRole('heading', { name: /Name and scope the work/i })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Live' })).toHaveAttribute('aria-pressed', 'true');
    expect(screen.getByRole('button', { name: 'Demo' })).toHaveAttribute('aria-pressed', 'false');
    expect(screen.getByRole('button', { name: 'Continue to scope' })).toBeInTheDocument();
    expect(within(workflowNav).getByRole('button', { name: /^Overview/i })).toHaveAttribute('aria-current', 'step');
    expect(within(workflowNav).getByRole('button', { name: /Scope/i })).toBeInTheDocument();
    expect(within(workflowNav).getByRole('button', { name: /Source Readiness/i })).toBeInTheDocument();
    expect(within(workflowNav).getByRole('button', { name: /Threat Modelling/i })).toBeInTheDocument();
    expect(within(workflowNav).getByRole('button', { name: /^Gaps/i })).toBeInTheDocument();
    expect(within(workflowNav).getByRole('button', { name: /^Report/i })).toBeInTheDocument();
    expect(within(workflowNav).getByRole('button', { name: /^References/i })).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Executive Summary' })).not.toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Risk Matrix' })).not.toBeInTheDocument();
    expect(screen.queryByText(/Readiness worksheet only: no event ingestion, replay, or automatic proof of wrongdoing/i)).not.toBeInTheDocument();
    expect(within(workflowNav).getByText('Current')).toBeInTheDocument();
    expect(within(workflowNav).getByText('Next')).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: /Start guided workflow/i })).not.toBeInTheDocument();
    expect(screen.getByRole('button', { name: /^Demo$/i })).toBeInTheDocument();
    expect(screen.getByRole('link', { name: /Security Engineering Hub/i })).toHaveAttribute('href', '/');
    expect(screen.queryByText(/Desktop-first|white-first|Seeded workshop readiness|Open report hub/i)).not.toBeInTheDocument();
  });

  it('opens Demo as an explanatory popup and supports cancelling with Escape', async () => {
    render(<App />);
    await userEvent.click(screen.getByRole('button', { name: /^Demo$/i }));
    const dialog = screen.getByRole('dialog', { name: /Explore the tool with example data/i });
    expect(within(dialog).getByRole('button', { name: /Cancel/i })).toHaveFocus();
    expect(within(dialog).getByText(/synthetic evidence/i)).toBeInTheDocument();
    await userEvent.keyboard('{Escape}');
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
    expect(screen.queryByText(/Demo data is loaded/i)).not.toBeInTheDocument();
  });

  it('starts as a real assessment and only seeds synthetic evidence after Demo explains the switch', async () => {
    render(<App />);
    const workflowNav = screen.getByRole('navigation', { name: /Assessment steps/i });
    const assessmentName = screen.getByRole('textbox', { name: /Assessment name/i });
    expect(assessmentName).toHaveValue('Untitled assessment');
    await userEvent.clear(assessmentName);
    await userEvent.type(assessmentName, 'Real assessment in progress');

    await userEvent.click(within(workflowNav).getByRole('button', { name: /Source Readiness/i }));

    expect(screen.getByText(/Verify each source individually/i)).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Verify all demo checks' })).not.toBeInTheDocument();

    await enterDemoMode();
    expect(screen.getByRole('button', { name: 'Live' })).toHaveAttribute('aria-pressed', 'false');
    expect(screen.getByRole('button', { name: 'Demo' })).toHaveAttribute('aria-pressed', 'true');
    expect(screen.getByText(/Demo data is loaded/i)).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Verify all demo checks' })).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Clear evidence' })).not.toBeInTheDocument();

    await userEvent.click(screen.getByRole('button', { name: 'Live' }));
    await userEvent.click(within(workflowNav).getByRole('button', { name: /^Overview/i }));
    expect(screen.getByRole('textbox', { name: /Assessment name/i })).toHaveValue('Real assessment in progress');
  });

  it('keeps workflow progression actions at the end of each working page', async () => {
    render(<App />);
    const workflowNav = screen.getByRole('navigation', { name: /Assessment steps/i });

    await userEvent.click(screen.getByRole('button', { name: 'Continue to scope' }));
    expect(screen.getByRole('contentinfo', { name: 'Scope workflow action' })).toHaveTextContent('Continue to source readiness');

    await userEvent.click(screen.getByRole('button', { name: 'Continue to source readiness' }));
    expect(screen.getByRole('contentinfo', { name: 'Source readiness workflow action' })).toHaveTextContent('Continue to threat modelling');

    await userEvent.click(screen.getByRole('button', { name: 'Continue to threat modelling' }));
    expect(screen.getByRole('contentinfo', { name: 'Threat modelling workflow action' })).toHaveTextContent('Continue to gaps');

    await userEvent.click(screen.getByRole('button', { name: 'Continue to gaps' }));
    expect(screen.getByRole('contentinfo', { name: 'Gaps workflow action' })).toHaveTextContent('Continue to report');
    expect(within(workflowNav).getByRole('button', { name: /^Gaps/i })).toHaveAttribute('aria-current', 'step');
  });

  it('supports the ordered workflow spine and local snapshot saving', async () => {
    render(<App />);
    const workflowNav = screen.getByRole('navigation', { name: /Assessment steps/i });

    await userEvent.click(within(workflowNav).getByRole('button', { name: /Scope/i }));
    await userEvent.click(within(workflowNav).getByRole('button', { name: /Source Readiness/i }));
    await userEvent.click(within(workflowNav).getByRole('button', { name: /Threat Modelling/i }));
    expect(screen.getByRole('heading', { name: /Follow the attack\. Check the evidence/i })).toBeInTheDocument();

    await userEvent.click(within(workflowNav).getByRole('button', { name: /^Report/i }));
    await userEvent.click(screen.getByRole('button', { name: 'Save locally' }));

    expect(screen.getAllByText(/Untitled assessment/i).length).toBeGreaterThan(0);
  });

  it('offers a primary/Alpha 3D switch over one threat model, with the primary view authoritative by default', async () => {
    render(<App />);
    const workflowNav = screen.getByRole('navigation', { name: /Assessment steps/i });
    await userEvent.click(within(workflowNav).getByRole('button', { name: /Threat Modelling/i }));

    const modeSwitch = screen.getByRole('group', { name: /Visualisation mode/i });
    expect(within(modeSwitch).getByRole('button', { name: 'Primary view' })).toHaveAttribute('aria-pressed', 'true');
    expect(within(modeSwitch).getByRole('button', { name: /3D map Alpha/i })).toHaveAttribute('aria-pressed', 'false');
    expect(screen.getByText(/Choose a scenario to see the actions, evidence, controls, gaps, and response work/i)).toBeInTheDocument();
    expect(screen.getByText(/Do not enter private logs, tenant identifiers, hostnames, credentials, or unsafe samples/i)).toBeInTheDocument();
  });

  it('renders the accepted attack chain in order in the 2D map', async () => {
    render(<App />);
    const workflowNav = screen.getByRole('navigation', { name: /Assessment steps/i });
    await userEvent.click(within(workflowNav).getByRole('button', { name: /Threat Modelling/i }));

    const map = screen.getByRole('region', { name: /Attack chain map/i });
    const headers = within(map)
      .getAllByRole('columnheader')
      .map((header) => header.textContent ?? '');

    expect(headers[0]).toContain('Stage');
    const chain = ['Preparation', 'Access', 'Misuse', 'Collection', 'Exfiltration', 'Concealment', 'Response'];
    expect(headers).toHaveLength(chain.length + 1);
    chain.forEach((label, index) => expect(headers[index + 1]).toContain(label));

    const flow = screen.getByRole('list', { name: /Directional attack chain/i });
    expect(within(flow).getAllByRole('listitem')).toHaveLength(chain.length);
    expect(within(flow).getAllByText('Actor')).toHaveLength(6);
    expect(within(flow).getByText('Defender')).toBeInTheDocument();
    expect(within(flow).getAllByText(/ready/i).length).toBeGreaterThan(0);
    expect(screen.getByText('Primary view legend')).toBeInTheDocument();
    expect(screen.getByText(/Evidence partial/i)).toBeInTheDocument();
  });

  it('keeps accepted risk visible as a gap that contributes no coverage', async () => {
    render(<App />);
    const workflowNav = screen.getByRole('navigation', { name: /Assessment steps/i });
    await userEvent.click(within(workflowNav).getByRole('button', { name: /Threat Modelling/i }));

    expect(screen.getAllByText(/accepted risk/i).length).toBeGreaterThan(0);
    expect(screen.getByText(/Accepted risk, no coverage/i)).toBeInTheDocument();
    expect(screen.getByText(/never counted as covered/i)).toBeInTheDocument();
    expect(screen.getByText(/It stays visible, stays neutral, and never renders as covered\./i)).toBeInTheDocument();
  });

  it('names what each control actually does instead of implying every control is a hard stop', async () => {
    render(<App />);
    const workflowNav = screen.getByRole('navigation', { name: /Assessment steps/i });
    await userEvent.click(within(workflowNav).getByRole('button', { name: /Threat Modelling/i }));

    const legend = screen.getByText(/What a control actually does/i).closest('div') as HTMLElement;
    expect(within(legend).getByText(/Raises a credible signal\. It does not stop the action\./i)).toBeInTheDocument();
    expect(within(legend).getByText(/Adds friction and buys response time\. It does not stop the action\./i)).toBeInTheDocument();
  });

  it('falls back to a flat simulation and points back at the primary view when WebGL is unavailable', async () => {
    render(<App />);
    const workflowNav = screen.getByRole('navigation', { name: /Assessment steps/i });
    await userEvent.click(within(workflowNav).getByRole('button', { name: /Threat Modelling/i }));
    await userEvent.click(screen.getByRole('button', { name: /3D map Alpha/i }));

    const notice = screen.getByRole('status');
    expect(within(notice).getByText(/3D map unavailable/i)).toBeInTheDocument();
    expect(within(notice).getByText(/Alpha 3D map is not supported in this environment because WebGL is unavailable or blocked/i)).toBeInTheDocument();
    expect(within(notice).getByText(/use the primary view above instead/i)).toBeInTheDocument();
    expect(screen.getByText(/3D map legend · Alpha/i)).toBeInTheDocument();
    expect(screen.getByText(/Lit telemetry\/evidence beam/i)).toBeInTheDocument();
    expect(screen.getByRole('img', { name: /Flat simulation of/i })).toBeInTheDocument();
  });

  it('uses a compact scenario selector instead of a large grid of scenario buttons', async () => {
    render(<App />);
    const workflowNav = screen.getByRole('navigation', { name: /Assessment steps/i });
    await userEvent.click(within(workflowNav).getByRole('button', { name: /Threat Modelling/i }));

    const scenarioSelect = screen.getByRole('combobox', { name: /Threat scenario/i });
    expect(screen.queryByRole('group', { name: /Threat scenario/i })).not.toBeInTheDocument();
    expect(scenarioSelect).toHaveValue('internal-pre-resignation-exfiltration');
    expect(scenarioSelect.querySelectorAll('option')).toHaveLength(17);
    expect(screen.getByText(/17 attack scenarios/i)).toBeInTheDocument();
    expect(screen.getAllByText(/Internal/i).length).toBeGreaterThan(0);
    expect(screen.getByText(/data exfiltration/i)).toBeInTheDocument();
    expect(screen.queryByRole('heading', { name: /Pre-resignation data theft/i })).not.toBeInTheDocument();

    await userEvent.click(screen.getByRole('button', { name: /Show investigation coverage details/i }));
    expect(screen.getByRole('heading', { name: /Pre-resignation data theft/i })).toBeInTheDocument();

    await userEvent.selectOptions(scenarioSelect, 'cyber-phishing-to-ransomware');
    expect(screen.getAllByText(/Convert one stolen session into estate-wide encryption/i).length).toBeGreaterThan(0);
  });

  it('provides a browsable insider-focused scenario library with ATT&CK references', async () => {
    render(<App />);
    const workflowNav = screen.getByRole('navigation', { name: /Assessment steps/i });
    await userEvent.click(within(workflowNav).getByRole('button', { name: /Threat Modelling/i }));

    await userEvent.click(screen.getByRole('button', { name: /Browse scenario library/i }));
    expect(screen.getByRole('region', { name: /Attack scenario library/i })).toBeInTheDocument();
    expect(screen.getByText(/9 insider and workforce scenarios/i)).toBeInTheDocument();
    expect(screen.getByText(/8 external cyber scenarios/i)).toBeInTheDocument();
    expect(screen.getByRole('radio', { name: /USB data theft/i })).toBeInTheDocument();
    expect(screen.getAllByText(/T1052\.001/i).length).toBeGreaterThan(0);
    expect(screen.getByText(/Indicative ATT&CK references/i)).toBeInTheDocument();

    await userEvent.selectOptions(screen.getByRole('combobox', { name: /Scenario type/i }), 'cyber');
    expect(screen.queryByRole('radio', { name: /USB data theft/i })).not.toBeInTheDocument();
    expect(screen.getByRole('radio', { name: /Phishing to ransomware/i })).toBeInTheDocument();
    expect(screen.getByRole('radio', { name: /Business email compromise/i })).toBeInTheDocument();

    await userEvent.click(screen.getByRole('radio', { name: /Business email compromise/i }));
    expect(screen.getByRole('heading', { name: /The invoice that changed banks/i })).toBeInTheDocument();
    expect(screen.getByText(/Damage to the business/i)).toBeInTheDocument();
    expect(screen.getByText(/Independent supplier verification and dual approval would prevent the payment/i)).toBeInTheDocument();
  });

  it('keeps supporting risk evidence and definitions in the final workflow step only', async () => {
    render(<App />);
    const workflowNav = screen.getByRole('navigation', { name: /Assessment steps/i });

    expect(screen.queryByRole('group', { name: /Reference views/i })).not.toBeInTheDocument();
    await userEvent.click(within(workflowNav).getByRole('button', { name: /^References/i }));

    expect(screen.getByRole('heading', { name: /Check how a result was reached/i })).toBeInTheDocument();
    expect(screen.getByRole('group', { name: /Reference views/i })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /Risk register/i })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /Research basis/i })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /Definitions/i })).toBeInTheDocument();
    await userEvent.click(screen.getByRole('button', { name: /Research basis/i }));
    expect(screen.getByRole('heading', { name: /Research basis and indicator boundaries/i })).toBeInTheDocument();
    expect(screen.getByRole('link', { name: /Insider Threat Knowledge Base/i })).toHaveAttribute('href', 'https://insiderthreat.mitre.org/');
    expect(screen.getByText(/opaque employee guilt score/i)).toBeInTheDocument();
    expect(screen.getByText(/Lawful purpose, minimum necessary fields/i)).toBeInTheDocument();
    expect(screen.queryByText(/Trust boundary|Handling caveats|Catalogue notes/i)).not.toBeInTheDocument();
  });

  it('makes prevention, evidence, and governance terms easy to find', async () => {
    render(<App />);
    const workflowNav = screen.getByRole('navigation', { name: /Assessment steps/i });
    await userEvent.click(within(workflowNav).getByRole('button', { name: /^References/i }));
    await userEvent.click(screen.getByRole('button', { name: /Definitions/i }));

    expect(screen.getByRole('heading', { name: /Clear terms\. Defensible decisions\./i })).toBeInTheDocument();
    expect(screen.getByText(/of \d+ terms/i)).toBeInTheDocument();

    await userEvent.type(screen.getByRole('textbox', { name: /Search glossary/i }), 'would stop');
    expect(screen.getByRole('heading', { name: /Preventive control/i })).toBeInTheDocument();
    expect(screen.getByRole('heading', { name: /Containment/i })).toBeInTheDocument();

    await userEvent.clear(screen.getByRole('textbox', { name: /Search glossary/i }));
    await userEvent.selectOptions(screen.getByRole('combobox', { name: /Glossary category/i }), 'Governance and privacy');
    expect(screen.getByRole('heading', { name: /Protected activity/i })).toBeInTheDocument();
    expect(screen.queryByRole('heading', { name: /DLP/i })).not.toBeInTheDocument();
  });

  it('moves between workflow steps with arrow keys', async () => {
    render(<App />);
    const workflowNav = screen.getByRole('navigation', { name: /Assessment steps/i });
    const overview = within(workflowNav).getByRole('button', { name: /^Overview/i });
    overview.focus();
    await userEvent.keyboard('{ArrowRight}');

    expect(within(workflowNav).getByRole('button', { name: /^Scope/i })).toHaveAttribute('aria-current', 'step');
    expect(screen.getByRole('heading', { name: /Confirm assessment scope/i })).toBeInTheDocument();
  });

  it('keeps metadata editable in overview', async () => {
    render(<App />);

    const assessmentName = screen.getByRole('textbox', { name: /Assessment name/i });
    await userEvent.clear(assessmentName);
    await userEvent.type(assessmentName, 'Stakeholder workshop overview');

    expect(screen.getByDisplayValue('Stakeholder workshop overview')).toBeInTheDocument();
  });

  it('explains why each log source is wanted and its positive and negative impact', async () => {
    render(<App />);
    const workflowNav = screen.getByRole('navigation', { name: /Assessment steps/i });
    await userEvent.click(within(workflowNav).getByRole('button', { name: /Source Readiness/i }));

    const idpCard = screen.getByRole('heading', { name: /IdP authentication/i }).closest('article') as HTMLElement;
    expect(within(idpCard).getByText(/Why this log source matters, impact, and handling guidance/i)).toBeInTheDocument();
    expect(within(idpCard).getByText('Why we want it')).toBeInTheDocument();
    expect(within(idpCard).getByText(/Links actions to authenticated sessions/i)).toBeInTheDocument();
    expect(within(idpCard).getByText('Positive impact')).toBeInTheDocument();
    expect(within(idpCard).getByText(/Fast account compromise triage/i)).toBeInTheDocument();
    expect(within(idpCard).getByText('Negative impact / caveat')).toBeInTheDocument();
    expect(within(idpCard).getByText(/false certainty about the human behind a session/i)).toBeInTheDocument();
  });

  it('filters the verification workspace to sources that still need attention', async () => {
    render(<App />);
    const workflowNav = screen.getByRole('navigation', { name: /Assessment steps/i });

    await enterDemoMode();
    await userEvent.click(within(workflowNav).getByRole('button', { name: /Source Readiness/i }));
    expect(screen.getByRole('heading', { name: /IdP authentication/i })).toBeInTheDocument();
    expect(screen.getByRole('heading', { name: /Email and collaboration/i })).toBeInTheDocument();

    await userEvent.click(screen.getByRole('checkbox', { name: /Needs attention only/i }));

    expect(screen.queryByRole('heading', { name: /IdP authentication/i })).not.toBeInTheDocument();
    expect(screen.getByRole('heading', { name: /Email and collaboration/i })).toBeInTheDocument();
  });

  it('consolidates report exports and snapshot actions in the report hub', async () => {
    render(<App />);
    const workflowNav = screen.getByRole('navigation', { name: /Assessment steps/i });

    await userEvent.click(within(workflowNav).getByRole('button', { name: /^Report/i }));

    expect(screen.getByRole('heading', { name: /Review the assessment before sharing it/i })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /Export Markdown/i })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /Export gaps CSV/i })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /Export assessment JSON/i })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /Open executive report/i })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /Save locally/i })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /Import snapshot/i })).toBeInTheDocument();
  });

  it('renders a polished printable executive report from the current assessment', async () => {
    const print = vi.spyOn(window, 'print').mockImplementation(() => undefined);
    render(<App />);
    const workflowNav = screen.getByRole('navigation', { name: /Assessment steps/i });
    await enterDemoMode();
    await userEvent.click(within(workflowNav).getByRole('button', { name: /^Report/i }));
    await userEvent.click(screen.getByRole('button', { name: /Open executive report/i }));

    expect(screen.getByRole('main')).toHaveClass('print-report-view');
    expect(screen.getByRole('note')).toHaveTextContent(/Demo — synthetic data/i);
    expect(screen.getByRole('heading', { name: /Example evidence gap assessment/i })).toBeInTheDocument();
    expect(screen.getByRole('img', { name: /Overall readiness/i })).toBeInTheDocument();
    expect(screen.getByRole('heading', { name: /Where the organisation is exposed/i })).toBeInTheDocument();
    expect(screen.getByRole('heading', { name: /Priority investigation gaps/i })).toBeInTheDocument();
    expect(screen.getByRole('heading', { name: /Priority evidence improvements/i })).toBeInTheDocument();
    expect(screen.getByText(/Strong blocking controls would prevent the path/i)).toBeInTheDocument();
    expect(screen.getByText(/Strong containment would stop it after detection/i)).toBeInTheDocument();
    expect(screen.queryByText(/critical controls stopped|Stopped \/ investigable/i)).not.toBeInTheDocument();

    await userEvent.click(screen.getByRole('button', { name: /Print or save PDF/i }));
    expect(print).toHaveBeenCalledOnce();
    await userEvent.click(screen.getByRole('button', { name: /Back to assessment/i }));
    expect(screen.getByRole('navigation', { name: /Assessment steps/i })).toBeInTheDocument();
    print.mockRestore();
  });

  it('provides an editable remediation lifecycle with accountability and validation evidence', async () => {
    render(<App />);
    const workflowNav = screen.getByRole('navigation', { name: /Assessment steps/i });

    await userEvent.click(within(workflowNav).getByRole('button', { name: /^Gaps/i }));
    expect(screen.getByRole('heading', { name: /Investigation paths with the greatest remaining risk/i })).toBeInTheDocument();
    expect(screen.getByRole('heading', { name: /Evidence improvements with the broadest impact/i })).toBeInTheDocument();
    await userEvent.click(screen.getAllByText('Update remediation record')[0]);

    expect(screen.getAllByLabelText('Accountable owner').length).toBeGreaterThan(0);
    expect(screen.getAllByLabelText('Engineering owner').length).toBeGreaterThan(0);
    expect(screen.getAllByLabelText('Business owner').length).toBeGreaterThan(0);
    expect(screen.getAllByLabelText('Detection / use-case mapping').length).toBeGreaterThan(0);
    expect(screen.getAllByLabelText('Validation method').length).toBeGreaterThan(0);
    expect(screen.getAllByLabelText('Evidence reference').length).toBeGreaterThan(0);

    await userEvent.selectOptions(screen.getAllByLabelText('Status')[0], 'accepted-risk');
    expect(screen.getAllByLabelText('Accepted-risk rationale').length).toBeGreaterThan(0);
    expect(screen.getAllByText(/Accepted risk needs a review date/i).length).toBeGreaterThan(0);
  });
});
