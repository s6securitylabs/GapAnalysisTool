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

## Product boundaries

The tool is an assessment workspace, not a monitoring or case-management system. It does not ingest raw telemetry, determine intent, create alerts, or prove wrongdoing. Assessment data, remediation records, and snapshots remain in browser memory or local storage until a user explicitly exports them.

Coverage means that required evidence is both usable and verified. Owning a product or collecting a log is not enough: critical checks and investigation-ready maturity are required. Accepted risk remains visible and contributes no coverage.

The 2D attack-chain map is the authoritative review and export view. The 3D simulation is an optional presentation of the same static model and must not introduce independent coverage facts.

The UI presents one ordered workflow: Overview, Scope, Source Readiness, Threat Modelling Scenarios, Gaps, Report, then References. The final References step contains the risk matrix, glossary, catalogue notes, and handling boundaries so supporting material does not interrupt every working page. Curated attack-chain scenarios cover internal misuse, privileged administration, data movement, third-party access, credential misuse, cloud audit readiness, sabotage, ransomware staging, and detection/response engineering.

Each log source explains why the evidence is wanted, the positive investigation or SOC-engineering impact it can create, and the negative impact or caveat that should constrain collection. This keeps analyst value, privacy, cost, and false-confidence tradeoffs visible in the same place as readiness scoring.

No ADR/design-record files are kept in this public product repository because repo guidance prohibits design records and private working notes here. Architecture and workflow decisions that affect users are reflected in this README and the public assessment guide instead.

See [Assessment guide](docs/ASSESSMENT-GUIDE.md) for workflow, remediation lifecycle, validation evidence, privacy safeguards, and handoff expectations.
