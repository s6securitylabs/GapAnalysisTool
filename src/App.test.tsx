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

describe('App integrated assessment experience', () => {
  it('defaults to overview with the six-step workflow and no executive summary route', () => {
    render(<App />);
    const workflowNav = screen.getByRole('navigation', { name: /Primary workflow/i });

    expect(screen.getByRole('heading', { name: /^Gaps Analysis Tool$/i })).toBeInTheDocument();
    expect(screen.getByRole('heading', { name: /Work the assessment in order\. Reference views stay off the main path\./i })).toBeInTheDocument();
    expect(screen.getByRole('heading', { name: /Assessment overview for workshop framing, verified readiness, and reporting/i })).toBeInTheDocument();
    expect(within(workflowNav).getByRole('button', { name: /^Overview/i })).toHaveAttribute('aria-pressed', 'true');
    expect(within(workflowNav).getByRole('button', { name: /Scope/i })).toBeInTheDocument();
    expect(within(workflowNav).getByRole('button', { name: /Source Readiness/i })).toBeInTheDocument();
    expect(within(workflowNav).getByRole('button', { name: /Threat Modelling Scenarios/i })).toBeInTheDocument();
    expect(within(workflowNav).getByRole('button', { name: /^Gaps/i })).toBeInTheDocument();
    expect(within(workflowNav).getByRole('button', { name: /^Report$/i })).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Executive Summary' })).not.toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Risk Matrix' })).toBeInTheDocument();
    expect(screen.getByText(/Readiness worksheet only: no event ingestion, replay, or automatic proof of wrongdoing/i)).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: /Start guided workflow/i })).not.toBeInTheDocument();
  });

  it('switches to real mode and removes the dangerous global verify-all shortcut', async () => {
    render(<App />);
    const workflowNav = screen.getByRole('navigation', { name: /Primary workflow/i });

    await userEvent.click(screen.getByRole('button', { name: 'Real assessment mode' }));
    await userEvent.click(within(workflowNav).getByRole('button', { name: /Source Readiness/i }));

    expect(screen.getByText(/Real assessment mode removes the risky global verify-all shortcut/i)).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Verify all demo checks' })).not.toBeInTheDocument();
  });

  it('supports the six-step workflow spine and local snapshot saving', async () => {
    render(<App />);
    const workflowNav = screen.getByRole('navigation', { name: /Primary workflow/i });

    await userEvent.click(within(workflowNav).getByRole('button', { name: /Scope/i }));
    await userEvent.click(within(workflowNav).getByRole('button', { name: /Source Readiness/i }));
    await userEvent.click(within(workflowNav).getByRole('button', { name: /Threat Modelling Scenarios/i }));
    expect(screen.getByRole('heading', { name: /Curated scenario-readiness review across threat-scenario flows and investigative control paths/i })).toBeInTheDocument();

    await userEvent.click(within(workflowNav).getByRole('button', { name: /^Report/i }));
    await userEvent.click(screen.getByRole('button', { name: 'Save locally' }));

    expect(screen.getAllByText(/FY26 gap analysis readiness review/i).length).toBeGreaterThan(0);
  });

  it('offers a 2D/3D switch over one threat model, with the 2D map authoritative by default', async () => {
    render(<App />);
    const workflowNav = screen.getByRole('navigation', { name: /Primary workflow/i });
    await userEvent.click(within(workflowNav).getByRole('button', { name: /Threat Modelling Scenarios/i }));

    const modeSwitch = screen.getByRole('group', { name: /Visualisation mode/i });
    expect(within(modeSwitch).getByRole('button', { name: '2D Attack Chain Map' })).toHaveAttribute('aria-pressed', 'true');
    expect(within(modeSwitch).getByRole('button', { name: '3D Threat Simulation' })).toHaveAttribute('aria-pressed', 'false');
    expect(screen.getByText(/authoritative view for review, print, and export/i)).toBeInTheDocument();
    expect(screen.getByText(/Do not enter private logs, tenant identifiers, hostnames, credentials, or unsafe samples/i)).toBeInTheDocument();
  });

  it('renders the accepted attack chain in order in the 2D map', async () => {
    render(<App />);
    const workflowNav = screen.getByRole('navigation', { name: /Primary workflow/i });
    await userEvent.click(within(workflowNav).getByRole('button', { name: /Threat Modelling Scenarios/i }));

    const map = screen.getByRole('region', { name: /Attack chain map/i });
    const headers = within(map)
      .getAllByRole('columnheader')
      .map((header) => header.textContent ?? '');

    expect(headers[0]).toContain('Stage');
    const chain = ['Preparation', 'Access', 'Misuse', 'Collection', 'Exfiltration', 'Concealment', 'Response'];
    expect(headers).toHaveLength(chain.length + 1);
    chain.forEach((label, index) => expect(headers[index + 1]).toContain(label));
  });

  it('keeps accepted risk visible as a gap that contributes no coverage', async () => {
    render(<App />);
    const workflowNav = screen.getByRole('navigation', { name: /Primary workflow/i });
    await userEvent.click(within(workflowNav).getByRole('button', { name: /Threat Modelling Scenarios/i }));

    expect(screen.getAllByText(/accepted risk contributes no coverage/i).length).toBeGreaterThan(0);
    expect(screen.getByText(/never counted as covered/i)).toBeInTheDocument();
    expect(screen.getByText(/It stays visible, stays neutral, and never renders as covered\./i)).toBeInTheDocument();
  });

  it('names what each control actually does instead of implying every control is a hard stop', async () => {
    render(<App />);
    const workflowNav = screen.getByRole('navigation', { name: /Primary workflow/i });
    await userEvent.click(within(workflowNav).getByRole('button', { name: /Threat Modelling Scenarios/i }));

    const legend = screen.getByText(/What a control actually does/i).closest('div') as HTMLElement;
    expect(within(legend).getByText(/Raises a credible signal\. It does not stop the action\./i)).toBeInTheDocument();
    expect(within(legend).getByText(/Adds friction and buys response time\. It does not stop the action\./i)).toBeInTheDocument();
  });

  it('falls back to a flat simulation and points back at the 2D map when WebGL is unavailable', async () => {
    render(<App />);
    const workflowNav = screen.getByRole('navigation', { name: /Primary workflow/i });
    await userEvent.click(within(workflowNav).getByRole('button', { name: /Threat Modelling Scenarios/i }));
    await userEvent.click(screen.getByRole('button', { name: '3D Threat Simulation' }));

    const notice = screen.getByRole('status');
    expect(within(notice).getByText(/3D Threat Simulation unavailable/i)).toBeInTheDocument();
    expect(within(notice).getByText(/3D is not supported in this environment because WebGL is unavailable or blocked/i)).toBeInTheDocument();
    expect(within(notice).getByText(/Try the 3D Threat Simulation in a modern browser with hardware acceleration and WebGL enabled/i)).toBeInTheDocument();
    expect(within(notice).getByText(/switch back to the 2D Attack Chain Map above/i)).toBeInTheDocument();
    expect(within(notice).getByText(/The 2D map is the authoritative view/i)).toBeInTheDocument();
    expect(screen.getByRole('img', { name: /Flat simulation of/i })).toBeInTheDocument();
  });

  it('switches between internal and external cyber scenarios in the same model', async () => {
    render(<App />);
    const workflowNav = screen.getByRole('navigation', { name: /Primary workflow/i });
    await userEvent.click(within(workflowNav).getByRole('button', { name: /Threat Modelling Scenarios/i }));

    const scenarioSwitch = screen.getByRole('group', { name: /Threat scenario/i });
    expect(within(scenarioSwitch).getAllByText('Internal').length).toBeGreaterThan(0);
    expect(within(scenarioSwitch).getAllByText('Cyber').length).toBeGreaterThan(0);

    await userEvent.click(within(scenarioSwitch).getByRole('button', { name: /External phishing to ransomware staging/i }));
    expect(screen.getByText(/Convert one stolen session into estate-wide encryption/i)).toBeInTheDocument();
  });

  it('keeps metadata editable in overview', async () => {
    render(<App />);

    const assessmentName = screen.getByRole('textbox', { name: /Assessment name/i });
    await userEvent.clear(assessmentName);
    await userEvent.type(assessmentName, 'Stakeholder workshop overview');

    expect(screen.getByDisplayValue('Stakeholder workshop overview')).toBeInTheDocument();
    expect(screen.getByText('Stakeholder workshop overview')).toBeInTheDocument();
  });

  it('filters the verification workspace to sources that still need attention', async () => {
    render(<App />);
    const workflowNav = screen.getByRole('navigation', { name: /Primary workflow/i });

    await userEvent.click(within(workflowNav).getByRole('button', { name: /Source Readiness/i }));
    expect(screen.getByRole('heading', { name: /IdP authentication/i })).toBeInTheDocument();
    expect(screen.getByRole('heading', { name: /Email and collaboration/i })).toBeInTheDocument();

    await userEvent.click(screen.getByRole('checkbox', { name: /Needs attention only/i }));

    expect(screen.queryByRole('heading', { name: /IdP authentication/i })).not.toBeInTheDocument();
    expect(screen.getByRole('heading', { name: /Email and collaboration/i })).toBeInTheDocument();
  });

  it('consolidates report exports and snapshot actions in the report hub', async () => {
    render(<App />);

    await userEvent.click(screen.getAllByRole('button', { name: 'Open report hub' })[0]);

    expect(screen.getByRole('heading', { name: /Export reports, move snapshots, and compare saved assessments/i })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /Export Markdown report/i })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /Export gaps CSV/i })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /Export JSON snapshot/i })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /Save locally/i })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /Import snapshot/i })).toBeInTheDocument();
  });
});
