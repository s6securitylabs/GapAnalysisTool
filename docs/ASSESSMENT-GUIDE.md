# Assessment guide

## Intended outcome

Use the tool to turn threat-scenario and telemetry-readiness findings into an accountable engineering backlog. A completed review should let program, business, and engineering owners answer:

- Which threat scenarios cannot be investigated or contained with current evidence?
- Which source, field, correlation, detection, or response gap causes the exposure?
- Who owns the risk, the business decision, and the engineering delivery?
- How will the team validate the change and where is the resulting evidence recorded?
- When will accepted risk be reviewed again?

## Workflow

1. Define the assessment scope, accountable owner, handling constraints, and any exclusions.
2. Verify each evidence source. Record maturity separately from the individual critical checks; collection alone does not establish readiness.
3. Review scenario and attack-chain views to understand where evidence or control behaviour changes the outcome.
4. Work the prioritized gap register. Replace the seeded guidance with actual owners, dates, use-case mappings, validation methods, and evidence references.
5. Export a Markdown summary for governance and a CSV register for engineering handoff. Save or export a JSON snapshot when a point-in-time baseline is needed.
6. Reassess after validation and compare against the saved baseline.

## Remediation lifecycle

| Status | Meaning | Exit criteria |
| --- | --- | --- |
| `not-started` | Finding is understood but not scheduled. | Accountable, business, and engineering owners accept the action. |
| `planned` | Delivery scope and target are agreed. | Work begins and the validation method is defined. |
| `in-progress` | Engineering or process work is active. | Validation completes or a blocker is recorded. |
| `blocked` | A named dependency prevents progress. | Dependency clears and target/SLA are revisited. |
| `accepted-risk` | An authorized owner accepts the unresolved exposure. | Rationale and review date are recorded; the item still contributes no coverage. |
| `verified` | The remediation outcome has been tested. | Validation method and evidence reference are recorded. |

Target date and SLA serve different purposes: the date is the current delivery commitment; SLA days expresses the expected service level and remains useful when the assessment is copied or dates are reset.

## Evidence and validation

An evidence reference should point to a durable record without embedding sensitive content in this static app. Suitable references include a ticket, approved test run, saved query, dashboard, runbook exercise, replay result, or evidence-package identifier.

Validation should exercise the claimed outcome. Examples include synthetic source events, controlled replay, parser field-population checks, telemetry canaries, detection readback, alert-to-case routing, runbook tabletop exercises, and retention/search tests. A dashboard screenshot alone does not prove source completeness or correlation quality.

## Privacy and safety

- Record the minimum information needed to govern the gap. Do not paste private logs, message content, personnel details, credentials, tenant identifiers, or unsafe samples into notes or evidence references.
- Workforce, communications, physical-access, and behavioural context require approved purpose limitation, minimum-necessary access, and auditability.
- Treat contextual signals as corroboration. Do not infer intent or wrongdoing from a workforce event, location, destination, peer deviation, or policy match alone.
- Keep false-positive reduction in the lifecycle: validation should cover authorized business activity, exceptions, peer/role context, and suppression expiry where relevant.

## Static architecture and integration handoff

The repository intentionally remains a client-side static application. Catalogue content provides generic defaults; assessment state holds the user’s source verification and remediation records. JSON snapshots preserve both, including compatibility defaults when older snapshots lack newer remediation fields.

Integration occurs through explicit exports. CSV is the engineering backlog handoff, Markdown is the governance summary, and JSON is the complete local assessment interchange format. A future connector should preserve this boundary by exchanging typed assessment records; it should not make the browser a telemetry store or silently claim verification from tool ownership.
