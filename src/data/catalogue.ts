import { buildAssessmentScenarios } from '../lib/build-assessment-scenarios';
import { threatModel } from './threat-model';

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
  | 'workforce-lifecycle'
  | 'identity-governance'
  | 'asset-custody'
  | 'case-management'
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
  'workforce-lifecycle': [
    { id: 'hr-lifecycle-dates', label: 'Joiner, mover, leaver, and contractor lifecycle', priority: 'critical', verificationQuestion: 'Do we have authoritative start, transfer, notice, leave, resignation, termination, and contractor end dates without collecting reasons that are not needed for the investigation?', requiredFields: ['employeeId', 'workerType', 'status', 'startDate', 'effectiveDate', 'contractEndDate'], objective: 'Correlate technical activity to defined workforce transition windows and verify timely control changes.' },
    { id: 'hr-role-context', label: 'Role, manager, team, location, and expected access', priority: 'critical', verificationQuestion: 'Can investigators verify the person’s current role, manager, department, work location, privileged duties, and approved access profile at the time of activity?', requiredFields: ['employeeId', 'role', 'department', 'manager', 'workLocation', 'accessProfile', 'effectiveDate'], objective: 'Distinguish legitimate job activity from access that is inconsistent with current duties or a recent move.' },
  ],
  'identity-governance': [
    { id: 'ig-access-recertification', label: 'Access recertification and entitlement reviews', priority: 'critical', verificationQuestion: 'Can we prove scheduled and event-driven access recertification, reviewer decisions, residual entitlements, and overdue reviews?', requiredFields: ['employeeId', 'campaignId', 'reviewer', 'entitlement', 'decision', 'dueDate', 'completedAt'], objective: 'Detect retained or excessive access after role changes and standing privilege reviews.' },
    { id: 'ig-transition-tasks', label: 'Joiner, mover, and leaver identity tasks', priority: 'critical', verificationQuestion: 'Can we prove identity provisioning, transfer, session revocation, and exception approvals completed on time with a named control owner?', requiredFields: ['employeeId', 'eventType', 'taskId', 'controlOwner', 'dueDate', 'completedAt', 'exceptionId'], objective: 'Detect control failures that leave unnecessary identity access available during workforce transitions.' },
    { id: 'ig-exception-approvals', label: 'Standing access and exception approvals', priority: 'recommended', verificationQuestion: 'Can investigators retrieve exception IDs, approvers, scope, expiry, and compensating controls for non-standard access?', requiredFields: ['exceptionId', 'approver', 'scope', 'expiry', 'compensatingControl'], objective: 'Separate approved residual access from uncontrolled privilege retention.' },
  ],
  'asset-custody': [
    { id: 'asset-assignment', label: 'Device and media assignment records', priority: 'critical', verificationQuestion: 'Do we have current assignment of laptops, phones, tokens, removable media, and high-value assets to a named worker or contractor?', requiredFields: ['employeeId', 'assetId', 'assetType', 'assignedAt', 'custodian', 'status'], objective: 'Prove which managed assets were under a worker’s custody during a transition or investigation window.' },
    { id: 'asset-return', label: 'Device return, wipe, and recovery', priority: 'critical', verificationQuestion: 'Can we prove device or media return, remote wipe, recovery-key handling, and residual unreturned assets after offboarding?', requiredFields: ['employeeId', 'assetId', 'returnedAt', 'wipeStatus', 'recoveryKeyHandled', 'exceptionId'], objective: 'Close physical and cryptographic custody gaps that keep data reachable after access should end.' },
    { id: 'asset-custody-audit', label: 'Custody change audit trail', priority: 'recommended', verificationQuestion: 'Can we show reassignment, lost/stolen reports, temporary loan, and custody exceptions with approver context?', requiredFields: ['assetId', 'fromCustodian', 'toCustodian', 'reason', 'approver', 'timestamp'], objective: 'Support chain-of-custody reconstruction for devices and media used in sensitive activity.' },
  ],
  'case-management': [
    { id: 'hr-case-context', label: 'Governed case, policy, training, and conflict context', priority: 'recommended', verificationQuestion: 'Can approved investigators retrieve only relevant case IDs, formal policy exceptions, required training or acknowledgement status, declared conflicts, corrective actions, and legal holds?', requiredFields: ['caseId', 'caseType', 'policyException', 'trainingStatus', 'conflictDeclaration', 'legalHold', 'approvalId'], objective: 'Add documented organisational context without ingesting unrestricted HR notes or treating a workplace issue as proof of intent.' },
    { id: 'hr-referral-governance', label: 'Human referral and multidisciplinary review governance', priority: 'recommended', verificationQuestion: 'Are HR, legal, privacy, security, and physical-security referrals recorded with source, approval, minimum-necessary summary, review outcome, retention, and appeal or correction path?', requiredFields: ['referralId', 'referralSource', 'approvalId', 'purpose', 'reviewers', 'outcome', 'retentionUntil'], objective: 'Create an accountable human review process for contextual signals and prevent automated employee risk scoring.' },
    { id: 'hr-access-controls', label: 'Privacy approval and access audit', priority: 'critical', verificationQuestion: 'Do we log who accessed workforce/case context, under what approval and lawful purpose, which fields were viewed, and when the access was reviewed?', requiredFields: ['viewer', 'approvalId', 'purpose', 'fieldsAccessed', 'accessTime', 'caseId', 'reviewDate'], objective: 'Enforce purpose limitation, least privilege, accountability, and review for sensitive workforce information.' },
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
    { id: 'siem-entity-enrichment', label: 'Identity, asset, data, role, and approved context enrichment', priority: 'recommended', verificationQuestion: 'Do correlated events carry identity, role, peer group, asset criticality, data sensitivity, and approved time-bounded transition or case context?', requiredFields: ['entityId', 'role', 'peerGroup', 'assetCriticality', 'dataSensitivity', 'contextType', 'contextEffectiveFrom', 'contextExpiresAt', 'approvalId'], objective: 'Turn raw logs into investigation-ready business context without treating an opaque person-risk score as evidence.' },
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
    id: 'workforce-lifecycle',
    name: 'Workforce lifecycle',
    category: 'Workforce context',
    description: 'Governed joiner, mover, leaver, and contractor dates plus role, manager, location, and expected-access profile for control timing.',
    commonFields: ['employeeId', 'workerType', 'status', 'role', 'department', 'manager', 'workLocation', 'accessProfile', 'effectiveDate'],
    collectionNotes: 'Use minimum-necessary structured lifecycle and role fields under a documented purpose and human review. Exclude medical details, protected attributes, private communications, rumours, and unstructured performance notes. Lifecycle context is a control-timing lead, not proof of intent.',
    verificationChecks: logSourceVerification['workforce-lifecycle'],
  },
  {
    id: 'identity-governance',
    name: 'Identity governance',
    category: 'Workforce context',
    description: 'Access recertification outcomes, transfer and offboarding task completion, session-revocation requests, and exception approvals.',
    commonFields: ['employeeId', 'eventType', 'reviewId', 'taskId', 'controlOwner', 'decision', 'dueDate', 'completedAt', 'exceptionId'],
    collectionNotes: 'Record objective control completion and approvals only. Do not score people; use these records to verify least privilege and timely entitlement change during transitions.',
    verificationChecks: logSourceVerification['identity-governance'],
  },
  {
    id: 'asset-custody',
    name: 'Asset custody',
    category: 'Workforce context',
    description: 'Device, badge, token, and removable-media assignment, return, recovery, and disposal evidence with chain of custody.',
    commonFields: ['employeeId', 'assetId', 'assetType', 'assignedAt', 'dueReturnAt', 'returnedAt', 'returnStatus', 'custodyEvent', 'approvalId'],
    collectionNotes: 'Limit collection to custody events needed for offboarding and investigation readiness. Possession or late return is a control lead requiring corroboration, not standalone proof of misuse.',
    verificationChecks: logSourceVerification['asset-custody'],
  },
  {
    id: 'case-management',
    name: 'Case management',
    category: 'Workforce context',
    description: 'Formal case, policy, training, and conflict context; multidisciplinary referral governance; and privacy access audit for sensitive workforce records.',
    commonFields: ['caseId', 'caseType', 'policyException', 'trainingStatus', 'conflictDeclaration', 'legalHold', 'referralId', 'approvalId', 'viewer', 'purpose'],
    collectionNotes: 'Use purpose limitation, least privilege, human review, field-level auditing, retention limits, and correction or appeal paths. Exclude unrestricted HR notes, medical details, protected attributes, private communications, and rumours.',
    verificationChecks: logSourceVerification['case-management'],
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
    description: 'Asset, identity, business role, peer baseline, data classification, approved case/transition context, and threat-intelligence enrichment used during correlation.',
    commonFields: ['entityId', 'assetCriticality', 'dataSensitivity', 'role', 'peerGroup', 'contextType', 'approvalId'],
    collectionNotes: 'Enrichment improves triage but is not direct evidence. Keep workforce context time-bounded, approval-backed, explainable, and separate from opaque employee risk scoring.',
    verificationChecks: logSourceVerification['siem-enrichment'],
  },
];

export const riskVectors: RiskVector[] = [
  {
    id: 'bulk-saas-download',
    domain: 'Data Exfiltration',
    name: 'Bulk download from SaaS before resignation',
    severity: 'critical',
    techniqueAlignment: 'Insider threat: SaaS collection/exfiltration with workforce context. ATT&CK: T1530 Data from Cloud Storage, T1567 Exfiltration Over Web Service.',
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
          { sourceId: 'workforce-lifecycle', strength: 'primary', rationale: 'Provides workforce timing and transition context.' },
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
    techniqueAlignment: 'Insider threat: cloud/SaaS collection, sharing, and exfiltration indicators. ATT&CK: T1530 Data from Cloud Storage, T1567.002 Exfiltration to Cloud Storage.',
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
    techniqueAlignment: 'Insider threat: source code/IP collection and staging before possible transfer. ATT&CK: T1213 Data from Information Repositories, T1560 Archive Collected Data.',
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
    techniqueAlignment: 'Insider threat: misuse of authorized privileged access and role-based risk. ATT&CK: T1078 Valid Accounts, T1548 Abuse Elevation Control Mechanism.',
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
    techniqueAlignment: 'Insider threat: unauthorized access expansion and privilege manipulation. ATT&CK: T1098 Account Manipulation, T1078.003 Local Accounts.',
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
    techniqueAlignment: 'Insider threat: policy bypass, unapproved tooling, and shadow IT data exposure. ATT&CK: T1528 Steal Application Access Token, T1550.001 Application Access Token.',
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
    techniqueAlignment: 'Insider threat: abuse of business systems and unauthorized modification. ATT&CK: T1565 Data Manipulation, T1078 Valid Accounts.',
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
          { sourceId: 'workforce-lifecycle', strength: 'supporting', rationale: 'Provides job role and department context.' },
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
    techniqueAlignment: 'Insider threat: sabotage, destruction, disruption, and monitoring disablement. ATT&CK: T1485 Data Destruction, T1489 Service Stop, T1490 Inhibit System Recovery.',
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
    techniqueAlignment: 'Insider threat: offboarding failure and continued use of valid access. ATT&CK: T1078 Valid Accounts.',
    description: 'Terminated or transferred personnel retain access and attempt to sign in or use sensitive applications.',
    investigationQuestions: [
      {
        id: 'q-term-date-access',
        question: 'Did the account authenticate or access systems after the termination/effective transfer date?',
        evidence: [
          { sourceId: 'workforce-lifecycle', strength: 'primary', rationale: 'Provides authoritative workforce status and dates.' },
          { sourceId: 'identity-governance', strength: 'supporting', rationale: 'Shows whether offboarding and access-removal tasks completed on time.' },
          { sourceId: 'idp-auth', strength: 'primary', rationale: 'Shows successful and failed authentication after status changes.' },
        ],
      },
      {
        id: 'q-post-term-actions',
        question: 'What sensitive systems or data were accessed after offboarding should have completed?',
        evidence: [
          { sourceId: 'saas-audit', strength: 'supporting', rationale: 'Shows application actions after status changes.' },
          { sourceId: 'file-access', strength: 'supporting', rationale: 'Shows file/repository access after status changes.' },
          { sourceId: 'asset-custody', strength: 'context', rationale: 'Shows whether assigned devices or media remained unreturned after the transition date.' },
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
    techniqueAlignment: 'Insider threat: role-based risk and unusual use of valid access. ATT&CK: T1078 Valid Accounts, T1213 Data from Information Repositories.',
    description: 'A user accesses systems, repositories, or records outside expected role, peer, location, or project patterns.',
    investigationQuestions: [
      {
        id: 'q-role-baseline',
        question: 'Is the accessed system or data consistent with the user role, project, and recent work context?',
        evidence: [
          { sourceId: 'workforce-lifecycle', strength: 'primary', rationale: 'Provides role, department, and manager context for role-based review.' },
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
    techniqueAlignment: 'Insider threat: indicator-building for pre-collection search and discovery activity. ATT&CK: T1083 File and Directory Discovery, T1087 Account Discovery, T1213 Data from Information Repositories.',
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
    techniqueAlignment: 'Insider threat: UAM/removable-media indicator and exfiltration pathway. ATT&CK: T1052.001 Exfiltration over USB, T1025 Data from Removable Media.',
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
    techniqueAlignment: 'Insider threat: email disclosure/exfiltration indicators. ATT&CK: T1114 Email Collection, T1114.003 Email Forwarding Rule, T1048 Exfiltration Over Alternative Protocol.',
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
    techniqueAlignment: 'Insider threat: concealment, control disablement, and investigative evidence integrity. ATT&CK: T1562.001 Impair Defenses: Disable or Modify Tools, T1070 Indicator Removal.',
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
    id: 'workforce-transition-control-failure',
    domain: 'Workforce Transition / Governance',
    name: 'Workforce transition coincides with access or control anomalies',
    severity: 'high',
    techniqueAlignment: 'Insider threat programme indicator: governed workforce-transition context correlated with observable cyber or control activity. ATT&CK techniques depend on the corroborating behaviour; workforce context alone is not an ATT&CK technique or proof of malicious intent.',
    description: 'A joiner, mover, leaver, contractor end, formal access review, or approved case window overlaps with retained access, unusual collection, privilege use, or incomplete transition controls.',
    investigationQuestions: [
      {
        id: 'q-workforce-transition-window',
        question: 'Can we establish an authoritative transition window, current duties, expected access, and completion status for required controls?',
        evidence: [
          { sourceId: 'workforce-lifecycle', strength: 'primary', rationale: 'Provides structured lifecycle, role, and manager context under governed access.' },
          { sourceId: 'identity-governance', strength: 'primary', rationale: 'Records access recertification, transition task completion, and exception approvals.' },
          { sourceId: 'asset-custody', strength: 'supporting', rationale: 'Shows device and media assignment or return obligations during the transition.' },
          { sourceId: 'idp-auth', strength: 'supporting', rationale: 'Shows whether roles, groups, sessions, or tokens changed in line with the workforce event.' },
          { sourceId: 'privileged-admin', strength: 'supporting', rationale: 'Shows privileged access and approvals that may require recertification or removal.' },
        ],
      },
      {
        id: 'q-workforce-corroboration-governance',
        question: 'Is the contextual signal purpose-limited, independently corroborated, and reviewed by authorised people before action?',
        evidence: [
          { sourceId: 'case-management', strength: 'primary', rationale: 'Records approval, minimum-necessary context, referral provenance, human review, retention, and audit history.' },
          { sourceId: 'siem-enrichment', strength: 'context', rationale: 'Correlates business role, asset criticality, and observable technical behaviour without becoming standalone evidence.' },
          { sourceId: 'physical-access', strength: 'context', rationale: 'May corroborate a defined incident timeline when facility evidence is relevant and lawfully in scope.' },
        ],
      },
    ],
  },
  {
    id: 'physical-cyber-anomaly',
    domain: 'Physical / Cyber Correlation',
    name: 'Physical access anomaly near cyber activity',
    severity: 'medium',
    techniqueAlignment: 'Insider threat: multidisciplinary cyber/physical/case-management correlation. No direct ATT&CK technique (physical-security signal); correlate with T1078 Valid Accounts sessions.',
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
    techniqueAlignment: 'Insider threat: negligent/mistaken internal types requiring corroboration and mitigation, not prediction. Not adversary-technique aligned; treat as policy/process weakness rather than an ATT&CK behaviour.',
    description: 'A user accidentally shares sensitive information through misaddressed email, overly broad SaaS sharing, or misunderstanding of policy.',
    investigationQuestions: [
      {
        id: 'q-nonmalicious-disclosure',
        question: 'Was sensitive data exposed and does the evidence indicate mistake, negligence, or policy/process weakness?',
        evidence: [
          { sourceId: 'dlp', strength: 'primary', rationale: 'Captures sensitive-data policy matches and action outcomes.' },
          { sourceId: 'email', strength: 'supporting', rationale: 'Shows recipient, attachment, and message metadata for misdirected email.' },
          { sourceId: 'saas-audit', strength: 'supporting', rationale: 'Shows sharing links, permissions, and external collaboration events.' },
          { sourceId: 'case-management', strength: 'context', rationale: 'Provides training, policy exception, or case context with restricted handling.' },
        ],
      },
    ],
  },
  {
    id: 'compromised-outsmarted-user',
    domain: 'Compromised / Outsmarted Internal',
    name: 'Compromised or outsmarted user causes account-driven activity',
    severity: 'high',
    techniqueAlignment: 'Insider threat: non-malicious compromised/outsmarted internal category with cyber corroboration. ATT&CK: T1566 Phishing, T1078 Valid Accounts, T1621 Multi-Factor Authentication Request Generation.',
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
    techniqueAlignment: 'Insider threat: coordinated internal activity across roles, systems, and evidence sources. ATT&CK: coordinated use of T1078 Valid Accounts, T1213 Data from Information Repositories, and T1567 Exfiltration Over Web Service across multiple accounts.',
    description: 'Multiple users coordinate access expansion, data collection, staged transfers, or approval bypass across systems.',
    investigationQuestions: [
      {
        id: 'q-collusion-timeline',
        question: 'Can we reconstruct a multi-user timeline showing coordinated access, collection, transfer, or approvals?',
        evidence: [
          { sourceId: 'idp-auth', strength: 'primary', rationale: 'Correlates user sessions, access changes, and authentication timing across accounts.' },
          { sourceId: 'saas-audit', strength: 'primary', rationale: 'Shows cross-user actions in business and collaboration applications.' },
          { sourceId: 'file-access', strength: 'supporting', rationale: 'Shows shared repository/file access and transfer sequence.' },
          { sourceId: 'case-management', strength: 'context', rationale: 'Adds conflict or case context under strict access controls.' },
        ],
      },
    ],
  },

  {
    id: 'ransomware-encryption-impact',
    domain: 'External Cyber',
    name: 'Ransomware encryption and service disruption',
    severity: 'critical',
    techniqueAlignment: 'External cyber: endpoint encryption and recovery denial. ATT&CK: T1486 Data Encrypted for Impact, T1490 Inhibit System Recovery.',
    description: 'An external actor encrypts business systems or disables recovery after initial access through phishing or malware.',
    investigationQuestions: [
      {
        id: 'q-ransomware-entry',
        question: 'How did the actor gain the initial foothold and reach encryption capability?',
        evidence: [
          { sourceId: 'email', strength: 'primary', rationale: 'Captures phishing delivery and malicious attachments or links.' },
          { sourceId: 'endpoint-edr', strength: 'primary', rationale: 'Shows process lineage, payload execution, and encryption activity.' },
          { sourceId: 'idp-auth', strength: 'supporting', rationale: 'Adds session and account-compromise context.' },
        ],
      },
      {
        id: 'q-ransomware-recovery',
        question: 'Were backups, recovery paths, or response ownership impaired?',
        evidence: [
          { sourceId: 'siem-enrichment', strength: 'primary', rationale: 'Correlates impact alerts, source health, and case timeline.' },
          { sourceId: 'privileged-admin', strength: 'supporting', rationale: 'Shows privileged recovery or sabotage of backup controls.' },
          { sourceId: 'cloud-storage', strength: 'supporting', rationale: 'Shows backup object deletion or recovery-store access.' },
        ],
      },
    ],
  },
  {
    id: 'saas-token-abuse',
    domain: 'External Cyber',
    name: 'Stolen SaaS OAuth or session token abuse',
    severity: 'critical',
    techniqueAlignment: 'External cyber: token replay against SaaS without password use. ATT&CK: T1528 Steal Application Access Token, T1078 Valid Accounts.',
    description: 'An attacker obtains delegated application consent or a stolen SaaS token and reads mail or files without interactive login.',
    investigationQuestions: [
      {
        id: 'q-token-consent',
        question: 'Can we prove which app or token gained access, with scopes, actor, and consent path?',
        evidence: [
          { sourceId: 'idp-auth', strength: 'primary', rationale: 'Records OAuth consent, app grants, and token issuance context.' },
          { sourceId: 'saas-audit', strength: 'primary', rationale: 'Shows subsequent mail/file access by the delegated principal.' },
          { sourceId: 'email', strength: 'supporting', rationale: 'Corroborates mailbox collection or rule changes.' },
        ],
      },
    ],
  },
  {
    id: 'business-email-compromise-payment',
    domain: 'External Cyber',
    name: 'Business email compromise payment diversion',
    severity: 'critical',
    techniqueAlignment: 'External cyber: mailbox takeover and invoice fraud. ATT&CK: T1566 Phishing, T1114 Email Collection, T1534 Internal Spearphishing.',
    description: 'An external actor hijacks or spoofs trusted mail threads to redirect a supplier payment.',
    investigationQuestions: [
      {
        id: 'q-bec-thread',
        question: 'Can we reconstruct mailbox access, rule changes, and payment-instruction alteration?',
        evidence: [
          { sourceId: 'email', strength: 'primary', rationale: 'Shows mailbox sessions, forwarding rules, and message metadata.' },
          { sourceId: 'idp-auth', strength: 'supporting', rationale: 'Shows account access and session anomalies around the fraud window.' },
          { sourceId: 'saas-audit', strength: 'supporting', rationale: 'Shows finance or ERP record changes tied to the request.' },
        ],
      },
    ],
  },
  {
    id: 'api-object-level-authz-failure',
    domain: 'External Cyber',
    name: 'Public API object-level authorization failure',
    severity: 'critical',
    techniqueAlignment: 'External cyber: broken object-level authorization and bulk enumeration. ATT&CK: T1190 Exploit Public-Facing Application, T1213 Data from Information Repositories.',
    description: 'An unauthenticated or low-privilege client enumerates customer records through valid API routes with weak object checks.',
    investigationQuestions: [
      {
        id: 'q-api-enum',
        question: 'Can we prove which API routes, object IDs, volumes, and client identities were involved?',
        evidence: [
          { sourceId: 'proxy-dns', strength: 'primary', rationale: 'Captures request volume, client, path, and destination context.' },
          { sourceId: 'saas-audit', strength: 'primary', rationale: 'Shows application/API audit of object reads and errors.' },
          { sourceId: 'siem-enrichment', strength: 'supporting', rationale: 'Adds asset criticality and known-good client baselines.' },
        ],
      },
    ],
  },
  {
    id: 'software-dependency-compromise',
    domain: 'External Cyber',
    name: 'Compromised software dependency',
    severity: 'critical',
    techniqueAlignment: 'External cyber: trusted update or dependency abuse. ATT&CK: T1195 Supply Chain Compromise, T1072 Software Deployment Tools.',
    description: 'A trusted package or update introduces malicious post-install behaviour into build or production environments.',
    investigationQuestions: [
      {
        id: 'q-supply-chain',
        question: 'Can we prove which package, pipeline, hosts, and outbound callbacks participated?',
        evidence: [
          { sourceId: 'file-access', strength: 'primary', rationale: 'Shows package install, artifact write, and repository access.' },
          { sourceId: 'endpoint-edr', strength: 'primary', rationale: 'Shows post-install process lineage on build or runtime hosts.' },
          { sourceId: 'proxy-dns', strength: 'supporting', rationale: 'Shows unexpected outbound destinations from the pipeline.' },
          { sourceId: 'saas-audit', strength: 'context', rationale: 'Shows CI/CD or package-registry audit events.' },
        ],
      },
      {
        id: 'q-supply-secrets',
        question: 'Were build secrets, tokens, or production credentials exposed?',
        evidence: [
          { sourceId: 'privileged-admin', strength: 'supporting', rationale: 'Shows privileged credential use after compromise.' },
          { sourceId: 'siem-enrichment', strength: 'primary', rationale: 'Supports recall, rotation, and case evidence.' },
        ],
      },
    ],
  },
  {
    id: 'public-cloud-exposure',
    domain: 'External Cyber',
    name: 'Public cloud storage exposure and harvesting',
    severity: 'high',
    techniqueAlignment: 'External cyber: unintended public object access. ATT&CK: T1530 Data from Cloud Storage, T1580 Cloud Infrastructure Discovery.',
    description: 'An unexpired public-access exception or misconfigured bucket allows anonymous enumeration and download of sensitive objects.',
    investigationQuestions: [
      {
        id: 'q-cloud-public',
        question: 'Which buckets or objects were publicly readable and for how long?',
        evidence: [
          { sourceId: 'cloud-storage', strength: 'primary', rationale: 'Captures ACL, policy, and object access events.' },
          { sourceId: 'siem-enrichment', strength: 'supporting', rationale: 'Adds exposure window and case correlation.' },
        ],
      },
      {
        id: 'q-cloud-harvest',
        question: 'Was anonymous harvesting observed, and what data left?',
        evidence: [
          { sourceId: 'proxy-dns', strength: 'supporting', rationale: 'Adds external request context where available.' },
          { sourceId: 'dlp', strength: 'supporting', rationale: 'Helps classify sensitive content involved.' },
        ],
      },
    ],
  },
  {
    id: 'availability-extortion',
    domain: 'External Cyber',
    name: 'Distributed denial of service and availability extortion',
    severity: 'high',
    techniqueAlignment: 'External cyber: volumetric or application-layer availability attack. ATT&CK: T1498 Network Denial of Service, T1499 Endpoint Denial of Service.',
    description: 'An external actor floods network or application paths to disrupt revenue services and demand payment.',
    investigationQuestions: [
      {
        id: 'q-ddos-signal',
        question: 'Which paths, dependencies, and customers were affected?',
        evidence: [
          { sourceId: 'proxy-dns', strength: 'primary', rationale: 'Shows edge traffic volume, sources, and blocked/allowed decisions.' },
          { sourceId: 'saas-audit', strength: 'supporting', rationale: 'Captures application latency, errors, and critical route health.' },
        ],
      },
      {
        id: 'q-ddos-response',
        question: 'Was upstream mitigation and continuity response timely and evidenced?',
        evidence: [
          { sourceId: 'siem-enrichment', strength: 'primary', rationale: 'Records incident ownership, provider actions, and recovery evidence.' },
          { sourceId: 'idp-auth', strength: 'context', rationale: 'Separates genuine customer traffic from attack noise where identity is present.' },
        ],
      },
    ],
  },
  {
    id: 'detection-pipeline-suppression',
    domain: 'External Cyber',
    name: 'Detection pipeline or logging suppression',
    severity: 'critical',
    techniqueAlignment: 'External cyber: impair defenses by disabling or redirecting telemetry. ATT&CK: T1562.008 Impair Defenses: Disable or Modify Cloud Logs, T1078.004 Valid Accounts: Cloud Accounts.',
    description: 'An attacker uses a compromised automation identity to suppress audit delivery or alert routing before impact.',
    investigationQuestions: [
      {
        id: 'q-pipeline-change',
        question: 'Which logging sinks, alert routes, or sensors changed?',
        evidence: [
          { sourceId: 'saas-audit', strength: 'primary', rationale: 'Captures configuration changes to audit and alert routing.' },
          { sourceId: 'idp-auth', strength: 'supporting', rationale: 'Attributes non-interactive automation identity use.' },
        ],
      },
      {
        id: 'q-pipeline-health',
        question: 'Would independent pipeline-health monitoring have raised the gap?',
        evidence: [
          { sourceId: 'siem-enrichment', strength: 'primary', rationale: 'Source freshness, volume, and parser health are the independent control.' },
          { sourceId: 'cloud-storage', strength: 'context', rationale: 'May show recovery-resource enumeration before impact.' },
        ],
      },
    ],
  },
];

export const threatFlow: ThreatFlowStep[] = [
  { id: 'trigger', label: 'Trigger / workforce context', description: 'Resignation, transfer, HR case, privileged change, compromised-account signal, or policy exception creates the context for review.', controls: ['workforce-lifecycle', 'identity-governance', 'idp-auth', 'siem-enrichment'] },
  { id: 'access', label: 'Access establishment', description: 'User authenticates, obtains privilege, starts VPN/app session, or consents a delegated app.', controls: ['idp-auth', 'vpn', 'privileged-admin', 'saas-audit'] },
  { id: 'discovery', label: 'Discovery / reconnaissance', description: 'User searches, browses repositories, enumerates records, or performs command-line discovery.', controls: ['saas-audit', 'file-access', 'endpoint-edr', 'siem-enrichment'] },
  { id: 'collection', label: 'Collection / staging', description: 'Sensitive records, files, messages, or objects are downloaded, exported, archived, or staged.', controls: ['saas-audit', 'file-access', 'cloud-storage', 'endpoint-edr', 'email'] },
  { id: 'transfer', label: 'Transfer / disclosure', description: 'Data moves through email, cloud share, web upload, removable media, external sharing, or public link.', controls: ['email', 'dlp', 'proxy-dns', 'cloud-storage', 'endpoint-edr'] },
  { id: 'impact', label: 'Impact / misuse', description: 'Business records are modified, resources deleted, controls disabled, or sensitive data exposed.', controls: ['saas-audit', 'privileged-admin', 'cloud-storage', 'file-access', 'dlp'] },
  { id: 'concealment', label: 'Concealment / evidence integrity', description: 'Logging, sensors, retention, permissions, or audit export paths are disabled or altered.', controls: ['privileged-admin', 'endpoint-edr', 'siem-enrichment', 'saas-audit'] },
];

/** Single source of truth: assessment scenarios are derived from the threat-model library. */
export const threatScenarios: ThreatScenario[] = buildAssessmentScenarios(threatModel.scenarios);

export const catalogue: Catalogue = {
  version: '0.5.0',
  summary: 'Evidence and investigation-readiness mappings, including privacy-governed workforce and organisational context. Validate technique mappings against your environment.',
  note: 'Evidence coverage and investigation readiness catalogue. Contextual signals require governance and corroboration, not prediction or standalone proof.',
  logSources,
  riskVectors,
  threatFlow,
  threatScenarios,
};
