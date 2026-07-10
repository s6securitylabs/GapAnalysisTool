export type GlossaryCategory =
  | 'Outcomes and decisions'
  | 'Evidence readiness'
  | 'Controls and identity'
  | 'Data and telemetry'
  | 'Governance and privacy'
  | 'Threat modelling';

export interface GlossaryTerm {
  term: string;
  category: GlossaryCategory;
  plainEnglish: string;
  whyItMatters: string;
}

export const glossary: GlossaryTerm[] = [
  {
    term: 'Strong control',
    category: 'Outcomes and decisions',
    plainEnglish: 'A control that is deployed, enforced, tested, and supported by current evidence.',
    whyItMatters: 'A strong blocking control would prevent the modelled action. A strong containment control would stop the path after detection.',
  },
  {
    term: 'Preventive control',
    category: 'Outcomes and decisions',
    plainEnglish: 'A control designed to prevent an action from succeeding.',
    whyItMatters: 'If it is tested and effective, it would stop the modelled path rather than merely record what happened.',
  },
  {
    term: 'Blocking control',
    category: 'Outcomes and decisions',
    plainEnglish: 'A preventive control that denies the attempted action at the point of enforcement.',
    whyItMatters: 'A strong blocking control would stop the action before the actor reaches the next stage.',
  },
  {
    term: 'Containment',
    category: 'Outcomes and decisions',
    plainEnglish: 'Action that limits spread, access, or damage after suspicious activity is detected.',
    whyItMatters: 'Strong containment would stop the path and limit impact, but it does not mean the initial action was prevented.',
  },
  {
    term: 'Detection',
    category: 'Outcomes and decisions',
    plainEnglish: 'A tested signal that would alert defenders to defined activity.',
    whyItMatters: 'Detection would expose the path. It would not stop it unless an enforced prevention or containment action follows.',
  },
  {
    term: 'Investigation-ready',
    category: 'Outcomes and decisions',
    plainEnglish: 'Analysts can search the required fields for the needed time window and export defensible evidence with provenance.',
    whyItMatters: 'It means the event could be investigated properly. It does not mean a strong control would have prevented it.',
  },
  {
    term: 'Accepted risk / not applicable',
    category: 'Outcomes and decisions',
    plainEnglish: 'A recorded decision that a gap is out of scope or will remain open for a justified reason.',
    whyItMatters: 'The gap is not fixed. The rationale, owner, compensating control, and review date must remain visible.',
  },
  {
    term: 'Evidence readiness',
    category: 'Evidence readiness',
    plainEnglish: 'How well a source can answer a defined investigation question using searchable, retained, attributable evidence.',
    whyItMatters: 'It measures whether defenders could prove or disprove what happened, not whether the attack would be prevented.',
  },
  {
    term: 'Normalized / correlatable',
    category: 'Evidence readiness',
    plainEnglish: 'The data is consistent enough to join users, devices, applications, sessions, or objects across sources.',
    whyItMatters: 'Correlation would expose linked activity, but missing fields or retention can still prevent a defensible investigation.',
  },
  {
    term: 'Normalization',
    category: 'Evidence readiness',
    plainEnglish: 'Converting different source formats into consistent fields and values.',
    whyItMatters: 'Reliable normalization prevents the same user, host, action, or timestamp from appearing as unrelated records.',
  },
  {
    term: 'Searchable, missing fields',
    category: 'Evidence readiness',
    plainEnglish: 'The source can be queried, but fields required for the investigation question are absent.',
    whyItMatters: 'A product can exist and still fail to prove identity, action, target, timing, or outcome.',
  },
  {
    term: 'Corroboration',
    category: 'Evidence readiness',
    plainEnglish: 'Independent evidence that supports or challenges an observation from another source.',
    whyItMatters: 'Serious escalation should not depend on one HR event, anomaly, badge record, or analytic result.',
  },
  {
    term: 'Alternative explanation',
    category: 'Evidence readiness',
    plainEnglish: 'A plausible benign or technical reason that could explain the observed activity.',
    whyItMatters: 'Testing alternatives prevents unusual activity from being treated as proof of malicious intent.',
  },
  {
    term: 'Exculpatory evidence',
    category: 'Evidence readiness',
    plainEnglish: 'Evidence that weakens an allegation or supports an authorised or benign explanation.',
    whyItMatters: 'It must be preserved with supporting evidence so the investigation does not become confirmation-driven.',
  },
  {
    term: 'Session lifecycle',
    category: 'Evidence readiness',
    plainEnglish: 'The start, continuation, renewal, revocation, and end of an authenticated session.',
    whyItMatters: 'It shows whether access remained usable and whether strong controls would terminate it when required.',
  },
  {
    term: 'Retention window',
    category: 'Evidence readiness',
    plainEnglish: 'How long source events remain searchable and exportable.',
    whyItMatters: 'Short retention can make a known path impossible to investigate after discovery.',
  },
  {
    term: 'Correlation health',
    category: 'Evidence readiness',
    plainEnglish: 'Whether sources are fresh, parsed correctly, and still joining to the expected identities, assets, and objects.',
    whyItMatters: 'A broken feed can create a silent blind spot even when the source is nominally connected.',
  },
  {
    term: 'Conditional access',
    category: 'Controls and identity',
    plainEnglish: 'Rules that allow, challenge, or block access based on identity, device, session, application, or approved context.',
    whyItMatters: 'A strong deny policy would prevent the modelled session. Its decision record would also explain what happened.',
  },
  {
    term: 'MFA',
    category: 'Controls and identity',
    plainEnglish: 'Multi-Factor Authentication: a second proof of identity such as an app prompt or hardware key.',
    whyItMatters: 'Strong phishing-resistant MFA would prevent many credential-only attacks; prompt and denial records also support investigation.',
  },
  {
    term: 'Token revocation',
    category: 'Controls and identity',
    plainEnglish: 'Invalidating active authentication tokens so existing sessions can no longer use them.',
    whyItMatters: 'Strong revocation would stop retained access even when the password has not changed.',
  },
  {
    term: 'IdP',
    category: 'Controls and identity',
    plainEnglish: 'Identity Provider: the system that authenticates users, such as Entra ID, Okta, or Google Workspace.',
    whyItMatters: 'Its sign-in, policy, token, and session records underpin most identity investigations and prevention controls.',
  },
  {
    term: 'PAM',
    category: 'Controls and identity',
    plainEnglish: 'Privileged Access Management: controls for approving, issuing, recording, and revoking administrative access.',
    whyItMatters: 'Strong PAM controls would prevent unapproved privilege use and preserve attribution for allowed sessions.',
  },
  {
    term: 'Vault checkout',
    category: 'Controls and identity',
    plainEnglish: 'The recorded release of a privileged credential or secret from a managed vault.',
    whyItMatters: 'It ties emergency or administrative access to a person, approval, target, and time window.',
  },
  {
    term: 'Break glass',
    category: 'Controls and identity',
    plainEnglish: 'Emergency privileged access reserved for urgent recovery when normal controls are unavailable.',
    whyItMatters: 'Strict approval, expiry, attribution, alerting, and review would prevent emergency access becoming a standing bypass.',
  },
  {
    term: 'Least privilege',
    category: 'Controls and identity',
    plainEnglish: 'Giving each identity only the access required for its current duties and approved period.',
    whyItMatters: 'Strong least-privilege controls would prevent unnecessary access and reduce the impact of misuse or compromise.',
  },
  {
    term: 'Access review',
    category: 'Controls and identity',
    plainEnglish: 'A scheduled or event-driven check that residual entitlements still match current duties, with a recorded decision and owner.',
    whyItMatters: 'Completed access reviews prove least privilege was reassessed; overdue reviews are control failures, not proof of misconduct.',
  },
  {
    term: 'Chain of custody',
    category: 'Evidence readiness',
    plainEnglish: 'A defensible record of who held, transferred, recovered, or disposed of an asset or evidence item and when.',
    whyItMatters: 'Without custody history, device return gaps and investigation evidence cannot be attributed or trusted.',
  },
  {
    term: 'Device return',
    category: 'Evidence readiness',
    plainEnglish: 'Evidence that assigned laptops, phones, tokens, or media were returned, wiped, or otherwise accounted for after a transition.',
    whyItMatters: 'Unreturned devices can leave data and credentials reachable after identity access should have ended.',
  },
  {
    term: 'Segregation of duties',
    category: 'Controls and identity',
    plainEnglish: 'Splitting a sensitive task so one person cannot both perform and approve it.',
    whyItMatters: 'Strong separation would prevent a single account from completing an unauthorised high-impact action alone.',
  },
  {
    term: 'Device posture',
    category: 'Controls and identity',
    plainEnglish: 'Evidence that a device meets required security conditions such as management, encryption, patch, and sensor state.',
    whyItMatters: 'A strong posture rule would prevent untrusted devices from reaching protected systems.',
  },
  {
    term: 'Assigned IP',
    category: 'Controls and identity',
    plainEnglish: 'The internal address allocated to a remote-access session.',
    whyItMatters: 'It connects VPN activity to downstream network events that may otherwise appear anonymous.',
  },
  {
    term: 'DLP',
    category: 'Data and telemetry',
    plainEnglish: 'Data Loss Prevention: controls that inspect sensitive data movement and may block, warn, quarantine, or record it.',
    whyItMatters: 'A strong enforced DLP policy would prevent defined transfers, but only on channels it actually inspects.',
  },
  {
    term: 'Policy disposition',
    category: 'Data and telemetry',
    plainEnglish: 'The action a policy took, such as allow, warn, block, quarantine, override, or audit only.',
    whyItMatters: 'It separates a detected event from one a strong control would actually prevent.',
  },
  {
    term: 'Channel coverage',
    category: 'Data and telemetry',
    plainEnglish: 'Which data paths a control inspects, such as email, endpoint, SaaS, web, cloud storage, or removable media.',
    whyItMatters: 'A strong policy cannot prevent movement through a channel it does not see.',
  },
  {
    term: 'Data classification',
    category: 'Data and telemetry',
    plainEnglish: 'A label describing the sensitivity, owner, regulatory status, or business value of data.',
    whyItMatters: 'It determines which strong controls should prevent access, sharing, export, or deletion.',
  },
  {
    term: 'Data events',
    category: 'Data and telemetry',
    plainEnglish: 'Object-level records of reads, writes, deletes, downloads, exports, shares, or permission changes.',
    whyItMatters: 'They show what happened to the data rather than only that a user authenticated.',
  },
  {
    term: 'Object action',
    category: 'Data and telemetry',
    plainEnglish: 'A specific operation performed on a file, record, message, repository, or cloud object.',
    whyItMatters: 'It identifies the action a control should prevent, detect, or preserve for investigation.',
  },
  {
    term: 'Object-level audit',
    category: 'Data and telemetry',
    plainEnglish: 'An audit trail that names the exact object, actor, action, time, and result.',
    whyItMatters: 'Without it, broad session logs cannot prove what data was touched or changed.',
  },
  {
    term: 'Permission change',
    category: 'Data and telemetry',
    plainEnglish: 'A change to who can view, modify, administer, or share a resource.',
    whyItMatters: 'Strong approval and enforcement would prevent unauthorised access expansion.',
  },
  {
    term: 'ACL change',
    category: 'Data and telemetry',
    plainEnglish: 'A change to an Access Control List governing who can read, write, administer, or share an object.',
    whyItMatters: 'An unauthorised ACL change can expose data even when no copy event is recorded.',
  },
  {
    term: 'External share',
    category: 'Data and telemetry',
    plainEnglish: 'Access granted to a person or account outside the approved organisation or tenant.',
    whyItMatters: 'Strong sharing restrictions would prevent sensitive data being exposed to unapproved recipients.',
  },
  {
    term: 'Public link',
    category: 'Data and telemetry',
    plainEnglish: 'A link that grants access without requiring a specifically approved identity.',
    whyItMatters: 'Strong tenant and data controls would prevent public links for sensitive material.',
  },
  {
    term: 'Audit export',
    category: 'Data and telemetry',
    plainEnglish: 'A defensible extraction of audit records for investigation, review, or preservation.',
    whyItMatters: 'It must retain timestamps, source identifiers, provenance, and chain-of-custody notes.',
  },
  {
    term: 'Mailbox audit',
    category: 'Data and telemetry',
    plainEnglish: 'Records of mailbox access, message actions, rules, delegation, exports, and administrative changes.',
    whyItMatters: 'It can expose forwarding, collection, disclosure, or privileged mailbox access.',
  },
  {
    term: 'Forwarding rule',
    category: 'Data and telemetry',
    plainEnglish: 'A mailbox rule that automatically sends or redirects messages to another destination.',
    whyItMatters: 'Strong external-forwarding controls would prevent persistent mail diversion.',
  },
  {
    term: 'Delegate access',
    category: 'Data and telemetry',
    plainEnglish: 'Permission for one identity to access or act through another user’s mailbox or application account.',
    whyItMatters: 'Approval and audit records distinguish legitimate delegation from shadow access.',
  },
  {
    term: 'Process lineage',
    category: 'Data and telemetry',
    plainEnglish: 'A chain showing which process launched each child process and with what command line.',
    whyItMatters: 'It helps prove staging, automation, compression, credential use, and concealment on endpoints.',
  },
  {
    term: 'Sensor tamper',
    category: 'Data and telemetry',
    plainEnglish: 'An attempt to stop, disable, uninstall, or reconfigure a security sensor.',
    whyItMatters: 'Strong tamper protection would prevent the sensor being silenced and would alert independently.',
  },
  {
    term: 'Removable media',
    category: 'Data and telemetry',
    plainEnglish: 'USB drives and other portable storage attached to an endpoint.',
    whyItMatters: 'Strong device control would prevent unauthorised writes of sensitive data to removable media.',
  },
  {
    term: 'Egress volume',
    category: 'Data and telemetry',
    plainEnglish: 'The amount of outbound data sent by a user, device, application, or session.',
    whyItMatters: 'It can expose unusual transfer, but must be tied to destination, object, approval, and business context.',
  },
  {
    term: 'DNS correlation',
    category: 'Data and telemetry',
    plainEnglish: 'Linking domain-resolution records to the user, device, session, and later network connection.',
    whyItMatters: 'It can expose destinations when proxy or application logs are incomplete.',
  },
  {
    term: 'Destination category',
    category: 'Data and telemetry',
    plainEnglish: 'A classification such as approved storage, personal email, newly registered domain, or anonymous sharing service.',
    whyItMatters: 'It helps route review, but category alone is not proof of data loss or malicious intent.',
  },
  {
    term: 'Badge event',
    category: 'Data and telemetry',
    plainEnglish: 'A recorded badge attempt at a door or controlled area, including time, location, and allow or deny result.',
    whyItMatters: 'It can corroborate a timeline but should not independently establish presence or intent.',
  },
  {
    term: 'Restricted area',
    category: 'Data and telemetry',
    plainEnglish: 'A physical location requiring explicit authorisation beyond ordinary site access.',
    whyItMatters: 'Strong physical access controls would prevent unauthorised entry and preserve the decision record.',
  },
  {
    term: 'Tailgate alarm',
    category: 'Data and telemetry',
    plainEnglish: 'A physical-security signal that more than one person may have entered on one authorised access event.',
    whyItMatters: 'It is a lead requiring validation against video, guard records, door behaviour, and reader health.',
  },
  {
    term: 'SIEM',
    category: 'Data and telemetry',
    plainEnglish: 'Security Information and Event Management: a platform that collects, searches, and correlates events from many systems.',
    whyItMatters: 'It exposes linked activity, but collection alone does not mean the required evidence is ready or a control would stop the path.',
  },
  {
    term: 'EDR',
    category: 'Data and telemetry',
    plainEnglish: 'Endpoint Detection and Response: software that records and responds to process, file, identity, and device activity.',
    whyItMatters: 'Strong EDR prevention would stop defined endpoint actions; telemetry and response records support investigation.',
  },
  {
    term: 'SaaS audit',
    category: 'Data and telemetry',
    plainEnglish: 'The application audit trail for views, downloads, exports, shares, permissions, tokens, and administrative changes.',
    whyItMatters: 'It is often the only evidence of collection or sharing inside business applications.',
  },
  {
    term: 'VPN',
    category: 'Data and telemetry',
    plainEnglish: 'Virtual Private Network: a managed remote-access tunnel with login, policy, network, and session records.',
    whyItMatters: 'Strong access policy would prevent untrusted remote sessions; session records support correlation.',
  },
  {
    term: 'OAuth',
    category: 'Data and telemetry',
    plainEnglish: 'A standard that lets an application receive delegated access without obtaining the user’s password.',
    whyItMatters: 'Strong consent governance would prevent unapproved applications gaining persistent access to mail, files, or SaaS data.',
  },
  {
    term: 'Purpose limitation',
    category: 'Governance and privacy',
    plainEnglish: 'Sensitive data is collected and used only for a specific approved security purpose.',
    whyItMatters: 'It prevents workforce, communications, or location evidence becoming general employee surveillance.',
  },
  {
    term: 'Minimum necessary',
    category: 'Governance and privacy',
    plainEnglish: 'Collect and expose only the fields required for the approved question.',
    whyItMatters: 'It prevents entire personnel, case, message, or location histories being copied when a coded fact is sufficient.',
  },
  {
    term: 'Data minimisation',
    category: 'Governance and privacy',
    plainEnglish: 'Limiting collection, access, retention, and export to the smallest defensible dataset.',
    whyItMatters: 'It reduces privacy harm, breach impact, and confirmation bias without weakening the defined control check.',
  },
  {
    term: 'Human review',
    category: 'Governance and privacy',
    plainEnglish: 'A qualified, authorised reviewer checks the evidence, alternatives, proportionality, and context before action.',
    whyItMatters: 'Workforce events and anomalies are leads, not proof. Human review prevents automated accusations or adverse action.',
  },
  {
    term: 'Workforce context',
    category: 'Governance and privacy',
    plainEnglish: 'Minimum-necessary lifecycle, role, sponsor, access-review, or approved case information used to test a control obligation.',
    whyItMatters: 'It should trigger a control check, never employee risk points or an assumption of malicious intent.',
  },
  {
    term: 'Protected activity',
    category: 'Governance and privacy',
    plainEnglish: 'Lawful conduct such as whistleblowing, safety reporting, complaints, protected leave, or union activity.',
    whyItMatters: 'Protected activity must not become a threat indicator or increase alert severity.',
  },
  {
    term: 'Control obligation',
    category: 'Governance and privacy',
    plainEnglish: 'A documented requirement that a control must act by a defined time or under defined conditions.',
    whyItMatters: 'The defensible question is whether the obligation failed, not whether a person’s circumstances looked risky.',
  },
  {
    term: 'Legal hold',
    category: 'Governance and privacy',
    plainEnglish: 'A formal requirement to preserve information relevant to litigation, regulation, or an authorised investigation.',
    whyItMatters: 'It changes deletion and retention rules but does not create authority for unrelated monitoring.',
  },
  {
    term: 'UEBA',
    category: 'Threat modelling',
    plainEnglish: 'User and Entity Behavior Analytics: analytics that compare activity with a historical, role, device, or peer baseline.',
    whyItMatters: 'It can expose unusual activity, but the result is a reviewable lead—not proof, intent, or a universal person-risk score.',
  },
  {
    term: 'ATT&CK',
    category: 'Threat modelling',
    plainEnglish: 'MITRE’s public catalogue of adversary techniques, with identifiers such as T1567 for exfiltration over web services.',
    whyItMatters: 'It describes how observed activity could occur. It does not establish that a person is an insider or acted maliciously.',
  },
  {
    term: 'Impossible travel',
    category: 'Threat modelling',
    plainEnglish: 'Authentication locations that appear too far apart for one person to travel between in the elapsed time.',
    whyItMatters: 'Validate VPNs, proxies, remote desktops, service accounts, shared infrastructure, and clock quality before escalation.',
  },
];
