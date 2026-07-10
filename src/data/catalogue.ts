export type Severity = 'critical' | 'high' | 'medium' | 'low';
export type EvidencePriority = 'critical' | 'recommended' | 'optional';

export type LogSourceId =
  | 'idp-auth'
  | 'endpoint-edr'
  | 'email'
  | 'dlp'
  | 'file-access'
  | 'vpn'
  | 'proxy-dns'
  | 'saas-audit'
  | 'hr-case'
  | 'physical-access'
  | 'privileged-admin'
  | 'cloud-storage'
  | 'siem-enrichment';

export interface LogVerificationCheck {
  id: string;
  label: string;
  priority: EvidencePriority;
  verificationQuestion: string;
  requiredFields: string[];
  objective: string;
}

export interface LogSource {
  id: LogSourceId;
  name: string;
  category: string;
  description: string;
  commonFields: string[];
  collectionNotes: string;
  verificationChecks: LogVerificationCheck[];
}

export interface EvidenceMapping {
  sourceId: LogSourceId;
  strength: 'primary' | 'supporting' | 'context';
  rationale: string;
}

export interface InvestigationQuestion {
  id: string;
  question: string;
  evidence: EvidenceMapping[];
}

export interface RiskVector {
  id: string;
  domain: string;
  name: string;
  severity: Severity;
  techniqueAlignment: string;
  description: string;
  investigationQuestions: InvestigationQuestion[];
}

export interface ThreatFlowStep {
  id: string;
  label: string;
  description: string;
  controls: LogSourceId[];
}

export interface ThreatScenario {
  id: string;
  title: string;
  objective: string;
  flowStepIds: string[];
  vectorIds: string[];
  criticalSources: LogSourceId[];
  recommendedSources: LogSourceId[];
}

export interface Catalogue {
  version: string;
  summary: string;
  note: string;
  logSources: LogSource[];
  riskVectors: RiskVector[];
  threatFlow: ThreatFlowStep[];
  threatScenarios: ThreatScenario[];
}

const logSourceVerification: Record<LogSourceId, LogVerificationCheck[]> = {
  'idp-auth': [
    { id: 'idp-login-logout', label: 'Interactive login/logout and session lifecycle', priority: 'critical', verificationQuestion: 'Do we have identity log data that shows successful logins, failed logins, logout/session end or token revocation with user, time, source IP, device, and application?', requiredFields: ['user', 'timestamp', 'result', 'sourceIp', 'deviceId', 'application', 'sessionId'], objective: 'Prove who authenticated, from where, on what device, and whether a risky session was established or ended.' },
    { id: 'idp-mfa-ca', label: 'MFA and conditional-access decision trail', priority: 'critical', verificationQuestion: 'Can we verify MFA prompts, approvals/denials, risk score, conditional-access policy result, and bypass/failure reason?', requiredFields: ['user', 'mfaResult', 'policyId', 'riskSignal', 'result', 'failureReason'], objective: 'Detect compromised/outsmarted users and policy bypass around sensitive activity.' },
    { id: 'idp-directory-change', label: 'Group, role, and app-consent changes', priority: 'recommended', verificationQuestion: 'Can we show role assignments, group membership changes, OAuth consent grants, and actor/target details?', requiredFields: ['actor', 'targetUser', 'groupOrRole', 'appId', 'scope', 'action'], objective: 'Prove access expansion or unauthorized delegated access.' },
  ],
  'endpoint-edr': [
    { id: 'edr-process-lineage', label: 'Process and command-line lineage', priority: 'critical', verificationQuestion: 'Do we have endpoint log data for process start, parent process, command line, user, host, hashes, and execution time?', requiredFields: ['host', 'user', 'process', 'parentProcess', 'commandLine', 'hash', 'timestamp'], objective: 'Identify staging, compression, scripted collection, anti-forensics, and local discovery.' },
    { id: 'edr-file-removable', label: 'File copy, archive, and removable-media activity', priority: 'critical', verificationQuestion: 'Can we verify files copied to USB/removable media, archive creation, sync clients, and file paths involved?', requiredFields: ['user', 'host', 'filePath', 'deviceId', 'operation', 'bytes', 'process'], objective: 'Prove local collection and removable-media exfiltration paths.' },
    { id: 'edr-sensor-tamper', label: 'Sensor health and tamper events', priority: 'recommended', verificationQuestion: 'Do we capture endpoint agent disablement, service stop, log deletion, or security-tool tamper attempts?', requiredFields: ['host', 'user', 'service', 'action', 'result', 'timestamp'], objective: 'Preserve evidence integrity and detect concealment.' },
  ],
  email: [
    { id: 'email-login-logout', label: 'Mailbox login/logout or access sessions', priority: 'critical', verificationQuestion: 'Do we have email log data that shows mailbox login/access and logout/session end where the platform emits it, including user, mailbox, IP, device, client app, and result?', requiredFields: ['user', 'mailbox', 'timestamp', 'clientApp', 'sourceIp', 'deviceId', 'sessionId', 'result'], objective: 'Tie mailbox activity to an authenticated session and distinguish user action from delegated/app access.' },
    { id: 'email-send-forward-attachments', label: 'Sent mail, forwarding rules, and attachments', priority: 'critical', verificationQuestion: 'Can we show external recipients, attachment names/sizes, forwarding/inbox rule creation, auto-forwarding destinations, and message IDs?', requiredFields: ['sender', 'recipient', 'messageId', 'attachmentName', 'attachmentSize', 'ruleAction', 'destinationDomain'], objective: 'Prove email exfiltration, misdirected disclosure, or persistence via forwarding rules.' },
    { id: 'email-admin-delegate', label: 'Mailbox delegation and admin audit', priority: 'recommended', verificationQuestion: 'Can we verify mailbox permission changes, eDiscovery/export actions, admin access, and delegated send-as/send-on-behalf actions?', requiredFields: ['actor', 'mailbox', 'permission', 'adminAction', 'exportId', 'timestamp'], objective: 'Detect privileged mailbox misuse or shadow collection.' },
  ],
  dlp: [
    { id: 'dlp-policy-match', label: 'Sensitive-data policy match with disposition', priority: 'critical', verificationQuestion: 'Do we have DLP events showing policy/rule, sensitive information type, user, channel, action taken, and disposition?', requiredFields: ['policy', 'rule', 'sensitiveType', 'user', 'channel', 'action', 'severity'], objective: 'Classify data involved in movement and prioritize true sensitive exposure.' },
    { id: 'dlp-channel-coverage', label: 'Channel coverage by email, endpoint, SaaS, and web', priority: 'recommended', verificationQuestion: 'Can we prove which exfiltration channels are inspected and which are blind spots?', requiredFields: ['channel', 'platform', 'policyScope', 'inspectionMode', 'coverageStatus'], objective: 'Avoid false confidence when DLP is only enabled for some data paths.' },
    { id: 'dlp-exception-override', label: 'User override, exception, and false-positive workflow', priority: 'optional', verificationQuestion: 'Can we see user justifications, policy overrides, approvals, and suppression/exception decisions?', requiredFields: ['user', 'justification', 'approver', 'exceptionId', 'expiry'], objective: 'Separate malicious activity from approved business exceptions and tuning gaps.' },
  ],
  'file-access': [
    { id: 'file-read-export-delete', label: 'Read, export, delete, clone, and permission events', priority: 'critical', verificationQuestion: 'Do we capture object-level file/repository/database reads, exports, clones, deletes, and permission changes?', requiredFields: ['actor', 'object', 'action', 'timestamp', 'bytes', 'repository', 'classification'], objective: 'Prove what data was touched, copied, deleted, or made accessible.' },
    { id: 'file-sensitive-labels', label: 'Data classification and ownership', priority: 'recommended', verificationQuestion: 'Can we map accessed objects to sensitivity, owner, project, customer, or regulated-data labels?', requiredFields: ['object', 'classification', 'owner', 'businessUnit', 'project'], objective: 'Turn raw access into business impact and priority.' },
    { id: 'file-baseline', label: 'Peer/role baseline for unusual access', priority: 'optional', verificationQuestion: 'Can we compare file/repo activity to normal role, project, peer, and historical baseline?', requiredFields: ['actor', 'role', 'peerGroup', 'baselineWindow', 'deviationScore'], objective: 'Identify suspicious but authorized access patterns.' },
  ],
  vpn: [
    { id: 'vpn-session-lifecycle', label: 'Remote access login/logout and duration', priority: 'critical', verificationQuestion: 'Do we have VPN log data showing login, logout/session end, assigned IP, source IP, user, device posture, and duration?', requiredFields: ['user', 'sourceIp', 'assignedIp', 'loginTime', 'logoutTime', 'duration', 'devicePosture'], objective: 'Correlate remote sessions with SaaS, file, and endpoint activity.' },
    { id: 'vpn-posture-deny', label: 'Device posture and policy decisions', priority: 'recommended', verificationQuestion: 'Can we show allow/deny decisions, unmanaged device use, split tunnel state, and posture failures?', requiredFields: ['user', 'deviceId', 'policy', 'decision', 'failureReason'], objective: 'Detect risky remote access conditions and compromised sessions.' },
    { id: 'vpn-geo-anomaly', label: 'Geo/IP and impossible-travel context', priority: 'optional', verificationQuestion: 'Can we enrich sessions with geo, ASN, reputation, and impossible-travel signals?', requiredFields: ['sourceIp', 'geo', 'asn', 'reputation', 'travelSignal'], objective: 'Prioritize anomalous remote sessions.' },
  ],
  'proxy-dns': [
    { id: 'proxy-upload-egress', label: 'Web upload and egress volume', priority: 'critical', verificationQuestion: 'Do we capture URL/domain, user/device mapping, upload bytes, method, action, and destination category for outbound web traffic?', requiredFields: ['user', 'host', 'url', 'domain', 'bytesOut', 'method', 'action'], objective: 'Prove data left through external web/storage destinations.' },
    { id: 'dns-domain-resolution', label: 'DNS query trail with device/user correlation', priority: 'recommended', verificationQuestion: 'Can we correlate DNS queries to user/device and identify newly seen, personal storage, or suspicious domains?', requiredFields: ['host', 'user', 'domain', 'queryTime', 'response', 'category'], objective: 'Add destination context where proxy visibility is incomplete.' },
    { id: 'proxy-block-allow-policy', label: 'Allow/block policy decision context', priority: 'optional', verificationQuestion: 'Can we show why traffic was allowed or blocked and which policy matched?', requiredFields: ['policy', 'category', 'action', 'reason', 'user'], objective: 'Support control effectiveness and policy tuning.' },
  ],
  'saas-audit': [
    { id: 'saas-object-actions', label: 'Object view/download/export/share events', priority: 'critical', verificationQuestion: 'Do we have SaaS audit events for view, download, export, report run, external share, and permission changes with actor/object/session?', requiredFields: ['actor', 'eventType', 'objectId', 'objectType', 'workspace', 'ip', 'userAgent'], objective: 'Prove business application collection, sharing, and tampering.' },
    { id: 'saas-login-logout', label: 'Application login/logout and session details', priority: 'recommended', verificationQuestion: 'Can we show app-specific login/logout or session lifecycle where separate from IdP?', requiredFields: ['actor', 'app', 'loginTime', 'logoutTime', 'sessionId', 'ip'], objective: 'Tie application actions to sessions and devices.' },
    { id: 'saas-admin-config', label: 'Admin/configuration and audit export changes', priority: 'recommended', verificationQuestion: 'Can we detect SaaS admin changes, audit-log disablement, retention changes, API token creation, and export jobs?', requiredFields: ['actor', 'adminAction', 'target', 'oldValue', 'newValue', 'timestamp'], objective: 'Detect privilege misuse and evidence tampering inside SaaS platforms.' },
  ],
  'hr-case': [
    { id: 'hr-status-dates', label: 'Employment status, role, and offboarding dates', priority: 'critical', verificationQuestion: 'Do we have authoritative employment status, transfer/resignation/termination dates, manager, department, and role?', requiredFields: ['employeeId', 'status', 'role', 'department', 'manager', 'effectiveDate'], objective: 'Correlate activity with workforce risk windows and offboarding objectives.' },
    { id: 'hr-case-context', label: 'Investigation/case and policy exception context', priority: 'recommended', verificationQuestion: 'Can approved investigators see relevant case IDs, policy exceptions, conflicts, training events, or legal holds with purpose limitation?', requiredFields: ['caseId', 'caseType', 'policyException', 'approval', 'legalHold', 'accessPurpose'], objective: 'Explain context without treating HR data as standalone proof.' },
    { id: 'hr-access-controls', label: 'Privacy approval and access audit', priority: 'critical', verificationQuestion: 'Do we log who accessed HR/case context, under what approval, and for what investigation purpose?', requiredFields: ['viewer', 'approvalId', 'purpose', 'accessTime', 'caseId'], objective: 'Enforce privacy/legal governance for sensitive workforce data.' },
  ],
  'physical-access': [
    { id: 'physical-entry-exit', label: 'Facility entry/exit and restricted-area access', priority: 'recommended', verificationQuestion: 'Do we have badge access data showing entry, exit where available, door/site, access result, and employee ID?', requiredFields: ['employeeId', 'badgeId', 'door', 'site', 'timestamp', 'accessResult'], objective: 'Correlate physical presence or restricted-area access with cyber activity.' },
    { id: 'physical-exceptions', label: 'Visitor, tailgate, lost badge, and security incidents', priority: 'optional', verificationQuestion: 'Can we include approved security exceptions, visitor records, tailgate alarms, and lost badge reports?', requiredFields: ['caseId', 'incidentType', 'site', 'employeeId', 'timestamp'], objective: 'Add corroborating context without over-weighting location data.' },
  ],
  'privileged-admin': [
    { id: 'pam-session-command', label: 'Privileged session, command, and vault checkout', priority: 'critical', verificationQuestion: 'Do we capture privileged role activation, vault checkout, session recording/commands, target, and admin identity?', requiredFields: ['adminUser', 'role', 'target', 'command', 'checkoutId', 'sessionId', 'timestamp'], objective: 'Prove or disprove privileged misuse and destructive action.' },
    { id: 'pam-approval-ticket', label: 'Change ticket and approval correlation', priority: 'critical', verificationQuestion: 'Can privileged actions be matched to approved tickets, maintenance windows, break-glass approvals, and approvers?', requiredFields: ['ticketId', 'approvalId', 'approver', 'maintenanceWindow', 'reason'], objective: 'Determine whether privileged actions met control objectives.' },
    { id: 'pam-role-change', label: 'Admin role and policy changes', priority: 'recommended', verificationQuestion: 'Can we detect admin role assignment changes, PAM policy edits, break-glass usage, and vault permission changes?', requiredFields: ['actor', 'targetUser', 'role', 'policy', 'oldValue', 'newValue'], objective: 'Identify privilege expansion and control bypass.' },
  ],
  'cloud-storage': [
    { id: 'cloud-object-read-share', label: 'Object read/write/delete/share and ACL changes', priority: 'critical', verificationQuestion: 'Do we have cloud data events for object read, write, delete, external share/public link, and ACL/bucket policy changes?', requiredFields: ['principal', 'bucket', 'object', 'operation', 'bytes', 'aclChange', 'timestamp'], objective: 'Prove sensitive cloud object access and exposure.' },
    { id: 'cloud-data-classification', label: 'Bucket/object sensitivity and owner context', priority: 'recommended', verificationQuestion: 'Can we map cloud objects to classification, application owner, environment, and business criticality?', requiredFields: ['bucket', 'object', 'classification', 'owner', 'environment'], objective: 'Prioritize high-impact cloud data gaps.' },
    { id: 'cloud-api-token', label: 'API key/service account and anomalous client context', priority: 'optional', verificationQuestion: 'Can we identify API token/service-account use, client/user-agent, source network, and unusual tooling?', requiredFields: ['principal', 'accessKeyId', 'userAgent', 'sourceIp', 'apiOperation'], objective: 'Separate user actions from automated or delegated access.' },
  ],
  'siem-enrichment': [
    { id: 'siem-entity-enrichment', label: 'Identity, asset, data, and peer-group enrichment', priority: 'recommended', verificationQuestion: 'Do correlated events carry user, asset, data sensitivity, role, peer group, criticality, and watchlist enrichment?', requiredFields: ['entityId', 'assetCriticality', 'userRisk', 'dataSensitivity', 'peerGroup', 'watchlist'], objective: 'Turn raw logs into investigation-ready risk context.' },
    { id: 'siem-correlation-health', label: 'Correlation health and telemetry freshness', priority: 'critical', verificationQuestion: 'Can we prove source freshness, parsing health, event volume drops, and normalization quality for each log source?', requiredFields: ['sourceId', 'lastSeen', 'parseStatus', 'eventVolume', 'dropRate', 'normalizationStatus'], objective: 'Avoid assuming a selected source is usable when ingestion or parsing is broken.' },
    { id: 'siem-retention-search', label: 'Retention and searchability by source', priority: 'critical', verificationQuestion: 'Can analysts search the needed fields for the required retention window and export evidence with chain-of-custody notes?', requiredFields: ['sourceId', 'retentionDays', 'searchableFields', 'exportMethod', 'caseId'], objective: 'Verify investigation readiness, not just collection existence.' },
  ],
};

export const logSources: LogSource[] = [
  {
    id: 'idp-auth',
    name: 'IdP authentication',
    category: 'Identity',
    description: 'Interactive and non-interactive sign-ins, MFA prompts, conditional access outcomes, token events.',
    commonFields: ['user', 'timestamp', 'ip', 'device', 'mfaResult', 'geo', 'riskSignal'],
    collectionNotes: 'Retain raw sign-in and audit events long enough to compare access changes before/after suspicious activity.',
    verificationChecks: logSourceVerification['idp-auth'],
  },
  {
    id: 'endpoint-edr',
    name: 'Endpoint / EDR telemetry',
    category: 'Endpoint',
    description: 'Process, file, removable media, archive creation, screen capture, and command telemetry from managed devices.',
    commonFields: ['host', 'user', 'process', 'commandLine', 'filePath', 'hash', 'deviceId'],
    collectionNotes: 'Prioritize process lineage, USB/removable media, compression utilities, and sensor health events.',
    verificationChecks: logSourceVerification['endpoint-edr'],
  },
  {
    id: 'email',
    name: 'Email and collaboration',
    category: 'Communications',
    description: 'Mailbox audit, forwarding rules, sent mail metadata, attachment activity, Teams/Slack-style message exports.',
    commonFields: ['sender', 'recipient', 'subject', 'attachmentName', 'ruleAction', 'messageId'],
    collectionNotes: 'Capture admin audit logs and user mailbox actions; contents may require legal approval.',
    verificationChecks: logSourceVerification['email'],
  },
  {
    id: 'dlp',
    name: 'DLP alerts',
    category: 'Data protection',
    description: 'Policy matches for sensitive data movement across endpoint, email, SaaS, and network channels.',
    commonFields: ['policy', 'rule', 'sensitiveType', 'severity', 'destination', 'user'],
    collectionNotes: 'Treat alert absence carefully: policies and inspection coverage may vary by data class and channel.',
    verificationChecks: logSourceVerification['dlp'],
  },
  {
    id: 'file-access',
    name: 'File access / repository audit',
    category: 'Data stores',
    description: 'Read, write, delete, clone, export, and permission events from file shares, code repos, databases, or document systems.',
    commonFields: ['actor', 'object', 'action', 'bytes', 'repository', 'classification'],
    collectionNotes: 'Normalize object identifiers and data labels to support per-user access baselines.',
    verificationChecks: logSourceVerification['file-access'],
  },
  {
    id: 'vpn',
    name: 'VPN / remote access',
    category: 'Network access',
    description: 'Remote access sessions, source IP, assigned IP, device posture, duration, and gateway decisions.',
    commonFields: ['user', 'sourceIp', 'assignedIp', 'devicePosture', 'sessionDuration'],
    collectionNotes: 'Useful context when cloud/SaaS logs lack trusted device or network details.',
    verificationChecks: logSourceVerification['vpn'],
  },
  {
    id: 'proxy-dns',
    name: 'Proxy / DNS',
    category: 'Network egress',
    description: 'Web destinations, DNS queries, upload volumes, category decisions, and blocked/allowed egress.',
    commonFields: ['user', 'host', 'domain', 'url', 'bytesOut', 'category', 'action'],
    collectionNotes: 'Collect user identity and device mapping; anonymous NAT logs alone are weak evidence.',
    verificationChecks: logSourceVerification['proxy-dns'],
  },
  {
    id: 'saas-audit',
    name: 'SaaS audit',
    category: 'SaaS',
    description: 'Audit events from CRM, productivity suites, ticketing, source code systems, and business applications.',
    commonFields: ['actor', 'eventType', 'objectId', 'workspace', 'ip', 'userAgent'],
    collectionNotes: 'APIs differ by license tier; validate export/share/download event fidelity per platform.',
    verificationChecks: logSourceVerification['saas-audit'],
  },
  {
    id: 'hr-case',
    name: 'HR / case management',
    category: 'Workforce context',
    description: 'Employment status, manager, termination/resignation dates, investigation case notes, policy exceptions.',
    commonFields: ['employeeId', 'status', 'department', 'manager', 'terminationDate', 'caseId'],
    collectionNotes: 'Use least-privilege access and clear handling rules for sensitive personnel data.',
    verificationChecks: logSourceVerification['hr-case'],
  },
  {
    id: 'physical-access',
    name: 'Physical access / badge events',
    category: 'Physical security',
    description: 'Badge access, facility entry/exit, restricted-area access, visitor exceptions, and security desk incidents.',
    commonFields: ['employeeId', 'badgeId', 'door', 'site', 'timestamp', 'accessResult', 'caseId'],
    collectionNotes: 'Use only for approved threat-scenario investigations with privacy/legal controls; correlate to cyber events rather than treating location as proof.',
    verificationChecks: logSourceVerification['physical-access'],
  },
  {
    id: 'privileged-admin',
    name: 'Privileged admin / PAM',
    category: 'Privileged access',
    description: 'Admin role activation, command/session records, vault checkout, break-glass account activity, change tickets.',
    commonFields: ['adminUser', 'target', 'role', 'command', 'ticketId', 'sessionRecording'],
    collectionNotes: 'Correlate privileged activity to approvals and maintenance windows.',
    verificationChecks: logSourceVerification['privileged-admin'],
  },
  {
    id: 'cloud-storage',
    name: 'Cloud storage audit',
    category: 'Cloud',
    description: 'Object reads, writes, deletes, public link changes, bucket policy changes, and external sharing.',
    commonFields: ['principal', 'bucket', 'object', 'operation', 'bytes', 'aclChange', 'region'],
    collectionNotes: 'Enable data event logging selectively where volume/cost is high; monitor sensitive buckets first.',
    verificationChecks: logSourceVerification['cloud-storage'],
  },
  {
    id: 'siem-enrichment',
    name: 'SIEM enrichment',
    category: 'Analytics',
    description: 'Asset, identity, geo, threat intel, watchlist, data classification, and UEBA enrichment used during correlation.',
    commonFields: ['entityId', 'assetCriticality', 'userRisk', 'dataSensitivity', 'watchlist'],
    collectionNotes: 'Enrichment improves triage but should not be counted as direct evidence by itself.',
    verificationChecks: logSourceVerification['siem-enrichment'],
  },
];

export const riskVectors: RiskVector[] = [
  {
    id: 'bulk-saas-download',
    domain: 'Data Exfiltration',
    name: 'Bulk download from SaaS before resignation',
    severity: 'critical',
    techniqueAlignment: 'Internal scenario scenario: SaaS collection/exfiltration with workforce context. ATT&CK: T1530 Data from Cloud Storage, T1567 Exfiltration Over Web Service.',
    description: 'An employee downloads unusually large volumes of documents or records from SaaS systems near resignation or termination.',
    investigationQuestions: [
      {
        id: 'q-bulk-download',
        question: 'Can we prove what data was downloaded, by whom, and whether it was sensitive?',
        evidence: [
          { sourceId: 'saas-audit', strength: 'primary', rationale: 'Records object download/export actions and actor metadata.' },
          { sourceId: 'dlp', strength: 'supporting', rationale: 'Adds sensitive data classification or policy matches.' },
          { sourceId: 'siem-enrichment', strength: 'context', rationale: 'Adds data sensitivity and baseline context.' },
        ],
      },
      {
        id: 'q-resignation-context',
        question: 'Was the activity close to resignation, termination, or an active HR case?',
        evidence: [
          { sourceId: 'hr-case', strength: 'primary', rationale: 'Provides workforce timing and case context.' },
          { sourceId: 'idp-auth', strength: 'supporting', rationale: 'Confirms account, device, and location context for the session.' },
        ],
      },
    ],
  },
  {
    id: 'external-share-cloud',
    domain: 'Data Exfiltration',
    name: 'Unusual cloud object reads followed by external sharing',
    severity: 'high',
    techniqueAlignment: 'Internal scenario scenario: cloud/SaaS collection, sharing, and exfiltration indicators. ATT&CK: T1530 Data from Cloud Storage, T1567.002 Exfiltration to Cloud Storage.',
    description: 'A user reads many sensitive cloud objects and creates public links, external shares, or permissive ACLs.',
    investigationQuestions: [
      {
        id: 'q-cloud-object-actions',
        question: 'Which objects were read or shared externally, and were permissions changed?',
        evidence: [
          { sourceId: 'cloud-storage', strength: 'primary', rationale: 'Captures object reads, ACL changes, and sharing actions.' },
          { sourceId: 'dlp', strength: 'supporting', rationale: 'Identifies sensitive data involved in the activity.' },
        ],
      },
      {
        id: 'q-egress-path',
        question: 'Is there network or destination evidence for exfiltration?',
        evidence: [
          { sourceId: 'proxy-dns', strength: 'primary', rationale: 'Shows egress destinations and upload volumes.' },
          { sourceId: 'vpn', strength: 'context', rationale: 'Adds remote session context.' },
        ],
      },
    ],
  },
  {
    id: 'repo-clone-archive',
    domain: 'Data Exfiltration',
    name: 'Sensitive repository clone or archive creation',
    severity: 'high',
    techniqueAlignment: 'Internal scenario scenario: source code/IP collection and staging before possible transfer. ATT&CK: T1213 Data from Information Repositories, T1560 Archive Collected Data.',
    description: 'A developer or contractor clones sensitive repositories or creates large archives outside normal patterns.',
    investigationQuestions: [
      {
        id: 'q-repo-access',
        question: 'Can we identify cloned repositories, exported packages, or unusual source access?',
        evidence: [
          { sourceId: 'file-access', strength: 'primary', rationale: 'Captures repository clone/export and file access audit events.' },
          { sourceId: 'saas-audit', strength: 'supporting', rationale: 'Adds SaaS-hosted code system audit events where applicable.' },
        ],
      },
      {
        id: 'q-archive-tooling',
        question: 'Did the endpoint stage data using compression, removable media, or sync tools?',
        evidence: [
          { sourceId: 'endpoint-edr', strength: 'primary', rationale: 'Shows process lineage, archive creation, USB, and sync utility execution.' },
          { sourceId: 'proxy-dns', strength: 'supporting', rationale: 'Shows uploads to external storage or code mirrors.' },
        ],
      },
    ],
  },
  {
    id: 'privileged-outside-window',
    domain: 'Privilege Misuse',
    name: 'Privileged access outside approved change window',
    severity: 'critical',
    techniqueAlignment: 'Internal scenario scenario: misuse of authorized privileged access and role-based risk. ATT&CK: T1078 Valid Accounts, T1548 Abuse Elevation Control Mechanism.',
    description: 'Admin commands or role activations occur without matching ticket, approval, or maintenance window.',
    investigationQuestions: [
      {
        id: 'q-admin-session',
        question: 'Which privileged role, target, and commands were used?',
        evidence: [
          { sourceId: 'privileged-admin', strength: 'primary', rationale: 'Records PAM vault checkout, role activation, commands, and sessions.' },
          { sourceId: 'endpoint-edr', strength: 'supporting', rationale: 'Adds host command/process evidence for endpoints or servers.' },
        ],
      },
      {
        id: 'q-ticket-match',
        question: 'Was there an approved change or incident ticket matching the action?',
        evidence: [
          { sourceId: 'saas-audit', strength: 'supporting', rationale: 'Ticketing SaaS audit can show changes to approvals and work items.' },
          { sourceId: 'siem-enrichment', strength: 'context', rationale: 'Correlates admin entities, target criticality, and change windows.' },
        ],
      },
    ],
  },
  {
    id: 'mass-role-escalation',
    domain: 'Privilege Misuse',
    name: 'Mass permission grant or role escalation',
    severity: 'high',
    techniqueAlignment: 'Internal scenario scenario: unauthorized access expansion and privilege manipulation. ATT&CK: T1098 Account Manipulation, T1078.003 Local Accounts.',
    description: 'A user grants broad access, escalates roles, or changes group membership at abnormal volume or scope.',
    investigationQuestions: [
      {
        id: 'q-role-changes',
        question: 'Which identities, groups, and privileged roles changed?',
        evidence: [
          { sourceId: 'idp-auth', strength: 'primary', rationale: 'Captures identity governance and directory audit changes.' },
          { sourceId: 'privileged-admin', strength: 'primary', rationale: 'Captures privileged role assignment and activation.' },
        ],
      },
      {
        id: 'q-downstream-access',
        question: 'Did the new access enable sensitive data or system actions?',
        evidence: [
          { sourceId: 'saas-audit', strength: 'supporting', rationale: 'Shows downstream application access after grants.' },
          { sourceId: 'file-access', strength: 'supporting', rationale: 'Shows sensitive file or repository access after grants.' },
        ],
      },
    ],
  },
  {
    id: 'oauth-shadow-it',
    domain: 'Policy Bypass / Shadow IT',
    name: 'OAuth app consent to unapproved third-party application',
    severity: 'medium',
    techniqueAlignment: 'Internal scenario scenario: policy bypass, unapproved tooling, and shadow IT data exposure. ATT&CK: T1528 Steal Application Access Token, T1550.001 Application Access Token.',
    description: 'A user authorizes an unapproved OAuth app that can read mail, files, or profile data.',
    investigationQuestions: [
      {
        id: 'q-oauth-consent',
        question: 'Which app was consented, what scopes were granted, and by whom?',
        evidence: [
          { sourceId: 'idp-auth', strength: 'primary', rationale: 'Records app consent, service principal, and scope grants.' },
          { sourceId: 'saas-audit', strength: 'supporting', rationale: 'Shows app activity inside SaaS platforms after consent.' },
        ],
      },
      {
        id: 'q-data-reach',
        question: 'Did the app access or move sensitive data?',
        evidence: [
          { sourceId: 'email', strength: 'supporting', rationale: 'Shows mailbox access/forwarding related to app usage.' },
          { sourceId: 'dlp', strength: 'supporting', rationale: 'Highlights sensitive data access or transfer events.' },
        ],
      },
    ],
  },
  {
    id: 'business-record-tamper',
    domain: 'Fraud / Abuse of Business Systems',
    name: 'Customer or account record tampering',
    severity: 'high',
    techniqueAlignment: 'Internal scenario scenario: abuse of business systems and unauthorized modification. ATT&CK: T1565 Data Manipulation, T1078 Valid Accounts.',
    description: 'An employee modifies customer, payroll, expense, or account records outside normal duties or approval paths.',
    investigationQuestions: [
      {
        id: 'q-record-change',
        question: 'Which business records changed, and what values changed?',
        evidence: [
          { sourceId: 'saas-audit', strength: 'primary', rationale: 'Business application audit trails show record changes and actor context.' },
          { sourceId: 'siem-enrichment', strength: 'context', rationale: 'Adds business role, peer group, and data criticality context.' },
        ],
      },
      {
        id: 'q-approval-chain',
        question: 'Were segregation-of-duties or approval rules bypassed?',
        evidence: [
          { sourceId: 'hr-case', strength: 'supporting', rationale: 'Provides job role, department, and case context.' },
          { sourceId: 'idp-auth', strength: 'supporting', rationale: 'Confirms authenticating user/session and potential anomalous access.' },
        ],
      },
    ],
  },
  {
    id: 'destructive-admin',
    domain: 'Sabotage / Disruption',
    name: 'Destructive admin commands or mass deletes',
    severity: 'critical',
    techniqueAlignment: 'Internal scenario scenario: sabotage, destruction, disruption, and monitoring disablement. ATT&CK: T1485 Data Destruction, T1489 Service Stop, T1490 Inhibit System Recovery.',
    description: 'A privileged or application user deletes resources, disables monitoring, or performs destructive commands at scale.',
    investigationQuestions: [
      {
        id: 'q-destruction-actions',
        question: 'What resources were deleted or disabled, and from which account/session?',
        evidence: [
          { sourceId: 'privileged-admin', strength: 'primary', rationale: 'Shows privileged command/session records and target systems.' },
          { sourceId: 'saas-audit', strength: 'primary', rationale: 'Shows application-level mass delete or configuration changes.' },
          { sourceId: 'cloud-storage', strength: 'supporting', rationale: 'Shows object deletes, lifecycle/policy changes, and cloud storage impact.' },
        ],
      },
      {
        id: 'q-monitoring-disabled',
        question: 'Were security controls, logging, or endpoint sensors disabled?',
        evidence: [
          { sourceId: 'endpoint-edr', strength: 'primary', rationale: 'Captures agent tamper and process/service stop events.' },
          { sourceId: 'siem-enrichment', strength: 'context', rationale: 'Highlights telemetry drops and asset criticality.' },
        ],
      },
    ],
  },
  {
    id: 'access-retained-post-term',
    domain: 'Offboarding / Workforce Risk',
    name: 'Access retained past termination date',
    severity: 'critical',
    techniqueAlignment: 'Internal scenario scenario: offboarding failure and continued use of valid access. ATT&CK: T1078 Valid Accounts.',
    description: 'Terminated or transferred personnel retain access and attempt to sign in or use sensitive applications.',
    investigationQuestions: [
      {
        id: 'q-term-date-access',
        question: 'Did the account authenticate or access systems after the termination/effective transfer date?',
        evidence: [
          { sourceId: 'hr-case', strength: 'primary', rationale: 'Provides authoritative workforce status and dates.' },
          { sourceId: 'idp-auth', strength: 'primary', rationale: 'Shows successful and failed authentication after status changes.' },
        ],
      },
      {
        id: 'q-post-term-actions',
        question: 'What sensitive systems or data were accessed after offboarding should have completed?',
        evidence: [
          { sourceId: 'saas-audit', strength: 'supporting', rationale: 'Shows application actions after status changes.' },
          { sourceId: 'file-access', strength: 'supporting', rationale: 'Shows file/repository access after status changes.' },
          { sourceId: 'vpn', strength: 'context', rationale: 'Adds remote session context for access attempts.' },
        ],
      },
    ],
  },
  {
    id: 'unusual-valid-access',
    domain: 'Access Misuse',
    name: 'Valid access to unusual systems or data',
    severity: 'high',
    techniqueAlignment: 'Internal scenario scenario: role-based risk and unusual use of valid access. ATT&CK: T1078 Valid Accounts, T1213 Data from Information Repositories.',
    description: 'A user accesses systems, repositories, or records outside expected role, peer, location, or project patterns.',
    investigationQuestions: [
      {
        id: 'q-role-baseline',
        question: 'Is the accessed system or data consistent with the user role, project, and recent work context?',
        evidence: [
          { sourceId: 'hr-case', strength: 'primary', rationale: 'Provides role, department, manager, and case context for role-based review.' },
          { sourceId: 'siem-enrichment', strength: 'supporting', rationale: 'Adds peer group, data sensitivity, and asset criticality context.' },
        ],
      },
      {
        id: 'q-unusual-access-events',
        question: 'Which systems, repositories, or SaaS objects were accessed and from what session?',
        evidence: [
          { sourceId: 'saas-audit', strength: 'primary', rationale: 'Shows application object access and actor/session metadata.' },
          { sourceId: 'file-access', strength: 'primary', rationale: 'Shows file, repository, database, or document access actions.' },
          { sourceId: 'idp-auth', strength: 'supporting', rationale: 'Confirms authentication, device, location, and risk context.' },
        ],
      },
    ],
  },
  {
    id: 'search-recon-sensitive-data',
    domain: 'Reconnaissance / Collection',
    name: 'Search and reconnaissance for sensitive data',
    severity: 'medium',
    techniqueAlignment: 'Internal scenario scenario: indicator-building for pre-collection search and discovery activity. ATT&CK: T1083 File and Directory Discovery, T1087 Account Discovery, T1213 Data from Information Repositories.',
    description: 'A user performs unusual searches, directory browsing, repository enumeration, or command-line discovery before accessing sensitive data.',
    investigationQuestions: [
      {
        id: 'q-search-terms-and-scope',
        question: 'What systems, keywords, repositories, or records were searched and how broad was the activity?',
        evidence: [
          { sourceId: 'saas-audit', strength: 'primary', rationale: 'Captures application search, export, and object-view events where available.' },
          { sourceId: 'file-access', strength: 'primary', rationale: 'Shows browsing, list, clone, and read activity across data stores.' },
          { sourceId: 'endpoint-edr', strength: 'supporting', rationale: 'Shows command-line discovery and local search tooling.' },
        ],
      },
    ],
  },
  {
    id: 'removable-media-exfil',
    domain: 'Data Exfiltration',
    name: 'Sensitive data copied to removable media',
    severity: 'high',
    techniqueAlignment: 'Internal scenario scenario: UAM/removable-media indicator and exfiltration pathway. ATT&CK: T1052.001 Exfiltration over USB, T1025 Data from Removable Media.',
    description: 'Sensitive files are staged or copied to USB or other removable storage outside normal duties.',
    investigationQuestions: [
      {
        id: 'q-removable-copy',
        question: 'Which files were copied to removable media, by which device and user?',
        evidence: [
          { sourceId: 'endpoint-edr', strength: 'primary', rationale: 'Captures removable media mount, file copy, process, and device identifiers.' },
          { sourceId: 'file-access', strength: 'supporting', rationale: 'Shows source object access and classification context.' },
          { sourceId: 'dlp', strength: 'supporting', rationale: 'Adds data classification and policy match details for removable media channels.' },
        ],
      },
    ],
  },
  {
    id: 'email-exfil-forwarding',
    domain: 'Data Exfiltration',
    name: 'Email forwarding or attachment exfiltration',
    severity: 'high',
    techniqueAlignment: 'Internal scenario scenario: email disclosure/exfiltration indicators. ATT&CK: T1114 Email Collection, T1114.003 Email Forwarding Rule, T1048 Exfiltration Over Alternative Protocol.',
    description: 'A user sends sensitive attachments externally or creates forwarding rules that route mail to non-approved destinations.',
    investigationQuestions: [
      {
        id: 'q-email-path',
        question: 'What messages, attachments, or forwarding rules sent data outside approved channels?',
        evidence: [
          { sourceId: 'email', strength: 'primary', rationale: 'Captures sent mail metadata, attachments, mailbox rules, and recipients.' },
          { sourceId: 'dlp', strength: 'supporting', rationale: 'Identifies sensitive content matches and policy outcomes.' },
          { sourceId: 'idp-auth', strength: 'context', rationale: 'Confirms account/session context for mailbox activity.' },
        ],
      },
    ],
  },
  {
    id: 'concealment-log-tamper',
    domain: 'Concealment / Evidence Integrity',
    name: 'Logging disabled or evidence tampered',
    severity: 'critical',
    techniqueAlignment: 'Internal scenario scenario: concealment, control disablement, and investigative evidence integrity. ATT&CK: T1562.001 Impair Defenses: Disable or Modify Tools, T1070 Indicator Removal.',
    description: 'An authorized user disables logging, removes audit trails, tampers with endpoint sensors, or changes retention/configuration to conceal activity.',
    investigationQuestions: [
      {
        id: 'q-logging-changes',
        question: 'Which logging, retention, sensor, or audit settings changed and who approved them?',
        evidence: [
          { sourceId: 'privileged-admin', strength: 'primary', rationale: 'Shows privileged commands, configuration changes, and approvals/session details.' },
          { sourceId: 'endpoint-edr', strength: 'primary', rationale: 'Captures sensor tamper, service stop, and local log deletion events.' },
          { sourceId: 'siem-enrichment', strength: 'supporting', rationale: 'Highlights telemetry dropouts and affected critical assets.' },
        ],
      },
    ],
  },
  {
    id: 'physical-cyber-anomaly',
    domain: 'Physical / Cyber Correlation',
    name: 'Physical access anomaly near cyber activity',
    severity: 'medium',
    techniqueAlignment: 'Internal scenario scenario: multidisciplinary cyber/physical/case-management correlation. No direct ATT&CK technique (physical-security signal); correlate with T1078 Valid Accounts sessions.',
    description: 'Badge or restricted-area activity is inconsistent with cyber sessions, device location, or role context during a sensitive event.',
    investigationQuestions: [
      {
        id: 'q-physical-correlation',
        question: 'Do physical access events corroborate or conflict with cyber sessions and device activity?',
        evidence: [
          { sourceId: 'physical-access', strength: 'primary', rationale: 'Shows facility and restricted-area access outcomes.' },
          { sourceId: 'idp-auth', strength: 'supporting', rationale: 'Shows authentication timing, device, and location context.' },
          { sourceId: 'vpn', strength: 'context', rationale: 'Adds remote access session details for impossible-travel or location conflicts.' },
        ],
      },
    ],
  },
  {
    id: 'negligent-mistaken-disclosure',
    domain: 'Non-malicious Threat Scenario',
    name: 'Negligent or mistaken sensitive-data disclosure',
    severity: 'medium',
    techniqueAlignment: 'Internal scenario scenario: negligent/mistaken internal types requiring corroboration and mitigation, not prediction. Not adversary-technique aligned; treat as policy/process weakness rather than an ATT&CK behaviour.',
    description: 'A user accidentally shares sensitive information through misaddressed email, overly broad SaaS sharing, or misunderstanding of policy.',
    investigationQuestions: [
      {
        id: 'q-nonmalicious-disclosure',
        question: 'Was sensitive data exposed and does the evidence indicate mistake, negligence, or policy/process weakness?',
        evidence: [
          { sourceId: 'dlp', strength: 'primary', rationale: 'Captures sensitive-data policy matches and action outcomes.' },
          { sourceId: 'email', strength: 'supporting', rationale: 'Shows recipient, attachment, and message metadata for misdirected email.' },
          { sourceId: 'saas-audit', strength: 'supporting', rationale: 'Shows sharing links, permissions, and external collaboration events.' },
          { sourceId: 'hr-case', strength: 'context', rationale: 'Provides training, policy exception, or case context with restricted handling.' },
        ],
      },
    ],
  },
  {
    id: 'compromised-outsmarted-user',
    domain: 'Compromised / Outsmarted Internal',
    name: 'Compromised or outsmarted user causes account-driven activity',
    severity: 'high',
    techniqueAlignment: 'Internal scenario scenario: non-malicious compromised/outsmarted internal category with cyber corroboration. ATT&CK: T1566 Phishing, T1078 Valid Accounts, T1621 Multi-Factor Authentication Request Generation.',
    description: 'An account or user is manipulated through phishing, token theft, social engineering, or deceptive workflow to perform risky actions.',
    investigationQuestions: [
      {
        id: 'q-account-compromise-context',
        question: 'Do identity, endpoint, and message signals suggest compromise or social engineering rather than intentional misuse?',
        evidence: [
          { sourceId: 'idp-auth', strength: 'primary', rationale: 'Shows anomalous sign-ins, MFA outcomes, device changes, and token/session context.' },
          { sourceId: 'email', strength: 'supporting', rationale: 'Shows phishing or social-engineering messages that may have triggered actions.' },
          { sourceId: 'endpoint-edr', strength: 'supporting', rationale: 'Shows malware, suspicious process, or credential-theft indicators.' },
          { sourceId: 'saas-audit', strength: 'context', rationale: 'Shows downstream application actions performed by the account.' },
        ],
      },
    ],
  },
  {
    id: 'collusion-cross-user',
    domain: 'Collusion',
    name: 'Cross-user collusion to access, collect, or transfer data',
    severity: 'critical',
    techniqueAlignment: 'Internal scenario scenario: coordinated internal activity across roles, systems, and evidence sources. ATT&CK: coordinated use of T1078 Valid Accounts, T1213 Data from Information Repositories, and T1567 Exfiltration Over Web Service across multiple accounts.',
    description: 'Multiple users coordinate access expansion, data collection, staged transfers, or approval bypass across systems.',
    investigationQuestions: [
      {
        id: 'q-collusion-timeline',
        question: 'Can we reconstruct a multi-user timeline showing coordinated access, collection, transfer, or approvals?',
        evidence: [
          { sourceId: 'idp-auth', strength: 'primary', rationale: 'Correlates user sessions, access changes, and authentication timing across accounts.' },
          { sourceId: 'saas-audit', strength: 'primary', rationale: 'Shows cross-user actions in business and collaboration applications.' },
          { sourceId: 'file-access', strength: 'supporting', rationale: 'Shows shared repository/file access and transfer sequence.' },
          { sourceId: 'hr-case', strength: 'context', rationale: 'Adds role, reporting chain, conflict, or case context under strict access controls.' },
        ],
      },
    ],
  },
];


export const threatFlow: ThreatFlowStep[] = [
  { id: 'trigger', label: 'Trigger / workforce context', description: 'Resignation, transfer, HR case, privileged change, compromised-account signal, or policy exception creates the context for review.', controls: ['hr-case', 'idp-auth', 'siem-enrichment'] },
  { id: 'access', label: 'Access establishment', description: 'User authenticates, obtains privilege, starts VPN/app session, or consents a delegated app.', controls: ['idp-auth', 'vpn', 'privileged-admin', 'saas-audit'] },
  { id: 'discovery', label: 'Discovery / reconnaissance', description: 'User searches, browses repositories, enumerates records, or performs command-line discovery.', controls: ['saas-audit', 'file-access', 'endpoint-edr', 'siem-enrichment'] },
  { id: 'collection', label: 'Collection / staging', description: 'Sensitive records, files, messages, or objects are downloaded, exported, archived, or staged.', controls: ['saas-audit', 'file-access', 'cloud-storage', 'endpoint-edr', 'email'] },
  { id: 'transfer', label: 'Transfer / disclosure', description: 'Data moves through email, cloud share, web upload, removable media, external sharing, or public link.', controls: ['email', 'dlp', 'proxy-dns', 'cloud-storage', 'endpoint-edr'] },
  { id: 'impact', label: 'Impact / misuse', description: 'Business records are modified, resources deleted, controls disabled, or sensitive data exposed.', controls: ['saas-audit', 'privileged-admin', 'cloud-storage', 'file-access', 'dlp'] },
  { id: 'concealment', label: 'Concealment / evidence integrity', description: 'Logging, sensors, retention, permissions, or audit export paths are disabled or altered.', controls: ['privileged-admin', 'endpoint-edr', 'siem-enrichment', 'saas-audit'] },
];

export const threatScenarios: ThreatScenario[] = [
  { id: 'pre-resignation-data-theft', title: 'Pre-resignation data theft', objective: 'Detect and investigate unusual access, collection, and transfer of sensitive data before departure.', flowStepIds: ['trigger', 'access', 'discovery', 'collection', 'transfer'], vectorIds: ['bulk-saas-download', 'repo-clone-archive', 'email-exfil-forwarding', 'search-recon-sensitive-data', 'external-share-cloud'], criticalSources: ['hr-case', 'idp-auth', 'saas-audit', 'file-access'], recommendedSources: ['dlp', 'email', 'endpoint-edr', 'proxy-dns'] },
  { id: 'privileged-sabotage', title: 'Privileged sabotage or disruption', objective: 'Prove whether privileged commands, deletes, or control disablement were approved and attributable.', flowStepIds: ['access', 'impact', 'concealment'], vectorIds: ['privileged-outside-window', 'destructive-admin', 'concealment-log-tamper'], criticalSources: ['privileged-admin', 'endpoint-edr', 'siem-enrichment'], recommendedSources: ['saas-audit', 'cloud-storage', 'idp-auth'] },
  { id: 'offboarding-failure', title: 'Offboarding failure / retained access', objective: 'Identify accounts or sessions that remain active after transfer, termination, or contractor end date.', flowStepIds: ['trigger', 'access', 'collection'], vectorIds: ['access-retained-post-term', 'unusual-valid-access'], criticalSources: ['hr-case', 'idp-auth'], recommendedSources: ['saas-audit', 'file-access', 'vpn'] },
  { id: 'shadow-it-oauth', title: 'Shadow IT OAuth data exposure', objective: 'Detect unapproved app consent and determine whether the app accessed mail, files, or SaaS data.', flowStepIds: ['access', 'collection', 'transfer'], vectorIds: ['oauth-shadow-it', 'email-exfil-forwarding'], criticalSources: ['idp-auth', 'saas-audit'], recommendedSources: ['email', 'dlp', 'proxy-dns'] },
  { id: 'business-system-fraud', title: 'Business-system fraud or record tampering', objective: 'Show who changed records, whether approvals were bypassed, and what business impact resulted.', flowStepIds: ['access', 'impact', 'concealment'], vectorIds: ['business-record-tamper', 'mass-role-escalation'], criticalSources: ['saas-audit', 'idp-auth'], recommendedSources: ['hr-case', 'siem-enrichment', 'privileged-admin'] },
  { id: 'compromised-account-driven', title: 'Compromised or outsmarted user', objective: 'Differentiate intentional internal misuse from phishing, token theft, social engineering, or malware-driven activity.', flowStepIds: ['access', 'collection', 'transfer'], vectorIds: ['compromised-outsmarted-user', 'negligent-mistaken-disclosure'], criticalSources: ['idp-auth', 'endpoint-edr'], recommendedSources: ['email', 'saas-audit', 'dlp'] },
  { id: 'physical-cyber-correlation', title: 'Physical/cyber anomaly', objective: 'Correlate badge/facility evidence with device, VPN, and identity sessions without treating location as standalone proof.', flowStepIds: ['trigger', 'access', 'collection'], vectorIds: ['physical-cyber-anomaly'], criticalSources: ['idp-auth'], recommendedSources: ['physical-access', 'vpn', 'endpoint-edr'] },
  { id: 'removable-media-exfil', title: 'Removable-media (USB) exfiltration', objective: 'Prove whether sensitive files were staged or copied to USB/removable media outside normal duties, and by which device and user.', flowStepIds: ['trigger', 'discovery', 'collection', 'transfer'], vectorIds: ['removable-media-exfil'], criticalSources: ['endpoint-edr'], recommendedSources: ['file-access', 'dlp', 'hr-case'] },
  { id: 'collusion-ring', title: 'Cross-user collusion', objective: 'Reconstruct a multi-user timeline of coordinated access, collection, transfer, or approval bypass across several internals.', flowStepIds: ['trigger', 'access', 'discovery', 'collection', 'transfer'], vectorIds: ['collusion-cross-user'], criticalSources: ['idp-auth', 'saas-audit'], recommendedSources: ['file-access', 'hr-case', 'siem-enrichment'] },
];

export const catalogue: Catalogue = {
  version: 'seed-0.2.0',
  summary: 'Seed catalogue for threat-scenario evidence coverage and investigation readiness. Technique mappings are indicative implementation hints for local validation.',
  note: 'Evidence coverage and investigation readiness catalogue. Contextual signals require governance and corroboration, not prediction or standalone proof.',
  logSources,
  riskVectors,
  threatFlow,
  threatScenarios,
};
