export interface GlossaryTerm {
  term: string;
  plainEnglish: string;
  whyItMatters: string;
}

export const glossary: GlossaryTerm[] = [
  {
    term: 'Investigation-ready',
    plainEnglish: 'Analysts can search the right fields for the needed time window and export defensible evidence.',
    whyItMatters: 'This is the threshold that should count as real readiness, not just log collection.',
  },
  {
    term: 'Normalized / correlatable',
    plainEnglish: 'The data is cleaned up enough to join users, devices, apps, or objects across sources.',
    whyItMatters: 'It reduces analyst effort, but it still may not be enough if key fields or retention are missing.',
  },
  {
    term: 'Searchable, missing fields',
    plainEnglish: 'You can query the source, but some fields needed for the investigation questions are absent.',
    whyItMatters: 'This often creates false confidence because a tool exists but cannot answer the hard questions.',
  },
  {
    term: 'Conditional access',
    plainEnglish: 'Rules that allow, challenge, or block access based on risk, device state, or location.',
    whyItMatters: 'The decision trail can explain why a risky session was allowed or stopped.',
  },
  {
    term: 'DLP',
    plainEnglish: 'Controls that detect sensitive data movement and may block, warn, or log it.',
    whyItMatters: 'DLP helps classify impact, but only where the policy actually inspects the channel in question.',
  },
  {
    term: 'Process lineage',
    plainEnglish: 'A chain showing which process launched which child process and with what command line.',
    whyItMatters: 'It helps prove staging, automation, compression, and concealment on endpoints.',
  },
  {
    term: 'Accepted risk / not applicable',
    plainEnglish: 'A conscious decision that a source is out of scope or not worth pursuing for a justified reason.',
    whyItMatters: 'It closes the gap administratively, but the justification should be explicit and reviewable.',
  },
  {
    term: 'Purpose limitation',
    plainEnglish: 'Sensitive data is accessed only for a specific approved investigative purpose.',
    whyItMatters: 'This is critical when HR, email, behavior, or physical-security context is involved.',
  },
  {
    term: 'SIEM',
    plainEnglish: 'Security Information and Event Management: the platform that collects, searches, and correlates logs from many systems.',
    whyItMatters: 'It is usually where an analyst actually runs the searches this tool assumes are possible.',
  },
  {
    term: 'EDR',
    plainEnglish: 'Endpoint Detection and Response: the security agent on laptops and servers that records process, file, and device activity.',
    whyItMatters: 'It is the main source for staging, USB copies, and attempts to disable security tools.',
  },
  {
    term: 'IdP',
    plainEnglish: 'Identity Provider: the system that authenticates users, such as Entra ID, Okta, or Google Workspace.',
    whyItMatters: 'Its sign-in logs are the backbone of almost every threat-scenario investigation.',
  },
  {
    term: 'MFA',
    plainEnglish: 'Multi-Factor Authentication: a second proof of identity such as an app prompt or hardware key.',
    whyItMatters: 'MFA prompts, approvals, and denials help separate a real user from a compromised account.',
  },
  {
    term: 'PAM',
    plainEnglish: 'Privileged Access Management: the vault and session recorder that controls and logs admin/root access.',
    whyItMatters: 'It is how you prove whether a destructive or sensitive admin action was approved.',
  },
  {
    term: 'DLP',
    plainEnglish: 'Data Loss Prevention: controls that detect sensitive data movement and may block, warn, or log it.',
    whyItMatters: 'DLP helps classify impact, but only where the policy actually inspects the channel in question.',
  },
  {
    term: 'OAuth',
    plainEnglish: 'A standard that lets a user grant a third-party app permission to read data (mail, files) without sharing a password.',
    whyItMatters: 'A consented but unapproved OAuth app is a common shadow-IT data-exposure path.',
  },
  {
    term: 'SaaS audit',
    plainEnglish: 'The audit log inside a cloud application (CRM, file store, ticketing) that records who viewed, downloaded, exported, or shared what.',
    whyItMatters: 'It is often the only place business-application collection and sharing is visible.',
  },
  {
    term: 'UEBA',
    plainEnglish: 'User and Entity Behavior Analytics: analytics that compare activity to a normal baseline for a person, device, or peer group.',
    whyItMatters: 'It adds context (unusual vs normal) but is a lead, not proof of wrongdoing.',
  },
  {
    term: 'VPN',
    plainEnglish: 'Virtual Private Network: a remote-access tunnel into the corporate network, with its own login and session logs.',
    whyItMatters: 'Its session records help place a user on the network at a time and location.',
  },
  {
    term: 'ACL change',
    plainEnglish: 'A change to an Access Control List: who is allowed to read, write, or share an object such as a file or storage bucket.',
    whyItMatters: 'Making data public or broadly shared is a key exposure and exfiltration signal.',
  },
  {
    term: 'Break-glass',
    plainEnglish: 'An emergency, highly privileged account used only in urgent situations under strict logging.',
    whyItMatters: 'Break-glass use outside an incident is a strong privileged-misuse indicator.',
  },
  {
    term: 'Impossible travel',
    plainEnglish: 'Two sign-ins from locations too far apart to travel between in the elapsed time.',
    whyItMatters: 'It suggests shared credentials, a proxy, or account compromise rather than one physical user.',
  },
  {
    term: 'Segregation of duties',
    plainEnglish: 'Splitting a sensitive task so no single person can both perform and approve it.',
    whyItMatters: 'Bypassing it is central to fraud and business-record tampering cases.',
  },
  {
    term: 'Legal hold',
    plainEnglish: 'A formal instruction to preserve data relevant to litigation or an investigation.',
    whyItMatters: 'It changes retention and access rules and must be respected during threat-scenario reviews.',
  },
  {
    term: 'Removable media',
    plainEnglish: 'USB drives and other portable storage that can be plugged into an endpoint.',
    whyItMatters: 'Copying files to removable media is a classic, hard-to-block exfiltration path.',
  },
  {
    term: 'ATT&CK',
    plainEnglish: 'A public catalogue of adversary techniques, each with an ID such as T1567 (exfiltration over web service).',
    whyItMatters: 'The technique IDs on each risk vector let detection engineers trace coverage to known behaviours.',
  },
];
