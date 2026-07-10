# GapAnalysisTool

GapAnalysisTool is a static web app for mapping threat scenarios to telemetry coverage, control behaviour, evidence gaps, and remediation actions.

The public mirror is `s6securitylabs/GapAnalysisTool`; the canonical internal origin is Forgejo `s6soc/GapAnalysisTool`.

## Development

```bash
pnpm install --frozen-lockfile
pnpm test
pnpm run typecheck
pnpm run lint
pnpm run build
```

The app is published into SecHub as a static generated artifact under `/gaps-analysis-tool/app/`.

## Use it

### Option A: SecHub web app (recommended)

Use the [SecHub web app](https://sechub.s6ops.com/gaps-analysis-tool/app/) for a zero-install assessment workspace. It requires no account, contains no application analytics or tracking code, and does not upload assessment content. Snapshots remain in your browser's local storage until you explicitly export them. Normal web infrastructure may retain ordinary HTTP access logs, but the app does not associate activity with an account or send assessment data to SecHub.

### Option B: run it yourself

For a fully self-hosted static copy, build and run the included Docker image locally:

```bash
git clone https://github.com/s6securitylabs/GapAnalysisTool.git
cd GapAnalysisTool
git checkout v1.0.0
docker build --pull -t gap-analysis-tool:1.0.0 .
docker run --rm --publish 127.0.0.1:18180:80 gap-analysis-tool:1.0.0
```

Open <http://127.0.0.1:18180>. The loopback binding keeps it local to the machine. Full Docker, Compose, non-Docker, privacy, and data-migration instructions are in the [installation and usage guide](docs/INSTALLATION.md).

## Product boundaries

The tool is an assessment workspace, not a monitoring or case-management system. It does not ingest raw telemetry, determine intent, create alerts, or prove wrongdoing. Assessment data, remediation records, and snapshots remain in browser memory or local storage until a user explicitly exports them.

Coverage means that required evidence is both usable and verified. Owning a product or collecting a log is not enough: critical checks and investigation-ready maturity are required. Accepted risk remains visible and contributes no coverage.

The 2D attack-chain map and optional 3D simulation present the same scenario model. Neither creates separate coverage facts.

The UI presents one ordered workflow: Overview, Scope, Source Readiness, Attack Scenarios, Gaps, Report, then References. A new Live assessment starts with blank evidence. Demo data is optional and requires explicit activation. The attack-scenario library contains 17 scenarios: nine insider/workforce scenarios and eight external cyber scenarios. Scenario detail includes indicative MITRE ATT&CK references where they fit; accidental and other non-adversarial events are not forced into ATT&CK mappings.

The Gaps step separates material investigation-path gaps from the source improvements needed to close them. The Report step provides Markdown, CSV, and JSON exports plus a polished printable HTML executive report with readiness graphics, risk distribution, domain coverage, weakest attack paths, and priority actions. Browser print can save the report as an A4 PDF.

Each log source explains why the evidence is wanted, the positive investigation or SOC-engineering impact it can create, and the negative impact or caveat that should constrain collection. This keeps analyst value, privacy, cost, and false-confidence tradeoffs visible in the same place as readiness scoring.

No ADR/design-record files are kept in this public product repository because repo guidance prohibits design records and private working notes here. Architecture and workflow decisions that affect users are reflected in this README and the public assessment guide instead.

See [Assessment guide](docs/ASSESSMENT-GUIDE.md) for workflow, remediation lifecycle, validation evidence, privacy safeguards, and handoff expectations.
