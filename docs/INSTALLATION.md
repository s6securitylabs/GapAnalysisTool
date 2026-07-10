# Installation and usage

Gaps Analysis Tool is a static assessment workspace. It does not ingest raw telemetry, create alerts, determine intent, or prove wrongdoing. Assessment data stays in the browser unless you explicitly export it.

## Option A: use the SecHub web app (recommended)

Open [Gaps Analysis Tool on SecHub](https://sechub.s6ops.com/gaps-analysis-tool/app/).

This is the simplest and recommended path. The application is a static browser app:

- no account or sign-in is required;
- it contains no application analytics or tracking code;
- it does not upload assessment content to a service;
- snapshots remain in your browser's local storage until you explicitly export JSON, CSV, or Markdown.

Your assessment data is therefore controlled by your browser profile. Clearing browser site data removes local snapshots. SecHub infrastructure may retain ordinary HTTP access logs, as with any public website, but the application does not associate them with an account or send your assessment content to SecHub.

Start in **Live** mode for a blank assessment. **Demo** loads synthetic example data only after confirmation.

## Option B: run it yourself

Use this option if you want to host the static app entirely on your own machine or network.

### Docker

The repository includes a multi-stage Dockerfile that builds the static app and serves it with nginx. The container has no application backend. Data entered into an assessment remains in the browser storage of the client that opens it.

```bash
git clone https://github.com/s6securitylabs/GapAnalysisTool.git
cd GapAnalysisTool
git checkout v1.0.0

docker build --pull -t gap-analysis-tool:1.0.0 .
docker run --rm --name gap-analysis-tool \
  --publish 127.0.0.1:18180:80 \
  gap-analysis-tool:1.0.0
```

Then open <http://127.0.0.1:18180>.

The loopback-only binding means the app is not exposed to other hosts. To make it reachable on a trusted network, replace `127.0.0.1:18180:80` with the specific interface and port you intend to expose, and put it behind your own TLS and access controls if appropriate.

To keep it running after you close the terminal:

```bash
docker run -d --restart unless-stopped --name gap-analysis-tool \
  --publish 127.0.0.1:18180:80 \
  gap-analysis-tool:1.0.0
```

Stop and remove it with:

```bash
docker rm -f gap-analysis-tool
```

### Docker Compose

For the repository's included Compose configuration:

```bash
docker compose up --build -d
```

It publishes the app at <http://127.0.0.1:18180>.

### Build without Docker

If you prefer to serve the generated files with your own web server:

```bash
corepack enable
pnpm install --frozen-lockfile
pnpm run build
```

Serve the resulting `dist/` directory from a static web server. Configure history fallback to `index.html` if your server requires it.

## Moving an assessment

Use the Report step to export JSON before moving between browsers or hosts. Import that JSON into the target app. The tool does not synchronise assessments automatically.

## Operational notes

- Back up exported JSON if the assessment matters. Browser storage is not a durable system of record.
- Restrict access to exported files. They may contain scope, evidence-readiness, remediation, and owner information.
- Review the [assessment guide](ASSESSMENT-GUIDE.md) before treating an output as a decision record.
