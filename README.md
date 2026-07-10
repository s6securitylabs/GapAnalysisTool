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
