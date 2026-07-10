# Assessment guide

## Intended outcome

Use the tool to turn threat-scenario and telemetry-readiness findings into an accountable engineering backlog. A completed review should let program, business, and engineering owners answer:

- Which threat scenarios cannot be investigated or contained with current evidence?
- Which source, field, correlation, detection, or response gap causes the exposure?
- Who owns the risk, the business decision, and the engineering delivery?
- How will the team validate the change and where is the resulting evidence recorded?
- When will accepted risk be reviewed again?

## Workflow

Follow the numbered UI progression from left to right:

1. **Overview:** name the assessment, assign its owner, and review the current readiness summary.
2. **Scope:** confirm handling constraints, in-scope evidence domains, and exclusions.
3. **Source Readiness:** verify each evidence source. Record maturity separately from individual critical checks; collection alone does not establish readiness. For every source, review why the log is wanted, what positive investigation or SOC-engineering impact it provides, and what negative impact, privacy/cost caveat, or false-confidence risk it introduces.
4. **Attack Scenarios:** choose from the compact scenario library, then review the directional 2D attack chain to see where evidence or control behaviour changes the outcome. Filter for insider/workforce or external cyber scenarios and use the indicative MITRE ATT&CK references as a starting point, not a compliance claim. The 3D view is optional.
5. **Gaps:** work the prioritized register. Replace guide data with actual owners, dates, use-case mappings, validation methods, and evidence references.
6. **Report:** export a Markdown summary and CSV engineering register. Save or export a JSON snapshot when a point-in-time baseline is needed, then compare after reassessment.
7. **References:** consult the risk matrix, glossary, catalogue notes, trust boundary, and handling caveats after the working assessment.

New assessments start with blank evidence. Select **New user guide** only when you want example data for learning the workflow; exit the guide before recording a real assessment.

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

Log rationale is part of validation, not decoration. A source should stay below investigation-ready until the reviewer can explain:

- **Why we want it:** which question the evidence answers and what other source it corroborates.
- **Positive impact:** what containment, triage, remediation, engineering, or governance decision improves when the log is reliable.
- **Negative impact / caveat:** privacy exposure, licensing or storage cost, noise, false-positive burden, missing-channel risk, or false confidence created by weak attribution.

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
