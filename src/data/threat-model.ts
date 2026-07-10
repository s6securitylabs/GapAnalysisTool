import type { LogSourceId, Severity } from './catalogue';

export type { Severity };

/**
 * Canonical Threat Model.
 *
 * One object holds every attack-chain scenario, evidence mapping, control, typed gap, and
 * remediation item. The 2D Attack Chain Map and the 3D Threat Simulation both render from
 * this module. Neither renderer may hold coverage state of its own: if a fact cannot be
 * expressed here, it cannot be shown in either mode.
 *
 * All content below is synthetic demo data. It carries no tenant identifiers, no customer
 * names, no real hostnames, and no log samples.
 */

/** Accepted attack chain. Order is fixed and shared by both renderers. */
export type AttackChainStageId =
  | 'preparation'
  | 'access'
  | 'misuse'
  | 'collection'
  | 'exfiltration'
  | 'concealment'
  | 'response';

export type ScenarioKind = 'internal' | 'cyber';
export type ThreatScenarioTheme =
  | 'insider-misuse'
  | 'privileged-admin'
  | 'data-exfiltration'
  | 'sabotage'
  | 'credential-misuse'
  | 'third-party'
  | 'ransomware'
  | 'cloud-saas'
  | 'detection-response';

/**
 * Accepted gap taxonomy. Accepted risk is a gap: it stays visible, stays grey, and
 * contributes no coverage in any view or export.
 */
export type GapType = 'telemetry' | 'detection' | 'response' | 'accepted-risk';

/** What a defensive technique actually does. Not every control is a hard stop. */
export type ControlEffect = 'block' | 'detect' | 'delay' | 'contain' | 'investigate';

/** Whether the modelled control did its job on this stage of this scenario. */
export type ControlOutcome = 'holds' | 'partial' | 'bypassed';

export type Confidence = 'high' | 'medium' | 'low';

/** Whether the evidence needed for this stage is actually there and usable. */
export type EvidenceStatus = 'present' | 'partial' | 'absent';

export interface AttackChainStage {
  id: AttackChainStageId;
  label: string;
  order: number;
  intent: string;
  defenderQuestion: string;
}

export interface AttackAction {
  summary: string;
  detail: string;
  /** Indicative ATT&CK technique reference, where a public mapping is useful. */
  technique?: string;
}

export interface EvidenceRef {
  sourceId: LogSourceId;
  signal: string;
  requiredFields: string[];
  status: EvidenceStatus;
}

export interface ControlRef {
  id: string;
  name: string;
  effect: ControlEffect;
  outcome: ControlOutcome;
  confidence: Confidence;
  note: string;
}

export interface ThreatGap {
  id: string;
  type: GapType;
  severity: Severity;
  confidence: Confidence;
  statement: string;
  consequence: string;
}

export interface RemediationItem {
  id: string;
  action: string;
  owner: string;
  targetDate: string;
  effort: 'low' | 'medium' | 'high';
  gapIds: string[];
}

export interface ScenarioStage {
  stageId: AttackChainStageId;
  action: AttackAction;
  evidence: EvidenceRef[];
  controls: ControlRef[];
  gaps: ThreatGap[];
  remediation: RemediationItem[];
  /**
   * False when the actor does not operate at this stage in this scenario — sabotage has no
   * exfiltration. Such a stage is neither covered nor a gap, it cannot halt the chain, and it
   * is excluded from the coverage denominator rather than counted as a free win.
   */
  actorPresent?: boolean;
}

export interface ThreatScenario {
  id: string;
  kind: ScenarioKind;
  title: string;
  actor: string;
  objective: string;
  summary: string;
  themes: ThreatScenarioTheme[];
  stages: ScenarioStage[];
}

export interface ThreatModel {
  version: string;
  note: string;
  safety: string;
  stages: AttackChainStage[];
  scenarios: ThreatScenario[];
}

export const attackChainStages: AttackChainStage[] = [
  {
    id: 'preparation',
    label: 'Preparation',
    order: 1,
    intent: 'The actor sets up: reconnaissance, tooling, staged accounts, or a workforce event that creates the opportunity.',
    defenderQuestion: 'Can we see the setup before anything of value is touched?',
  },
  {
    id: 'access',
    label: 'Access',
    order: 2,
    intent: 'The actor authenticates, escalates privilege, or consents a delegated application to reach the target.',
    defenderQuestion: 'Can we prove who reached the target, from where, and under what authorisation?',
  },
  {
    id: 'misuse',
    label: 'Misuse',
    order: 3,
    intent: 'Legitimate privilege, tooling, or business process is turned to an unintended purpose.',
    defenderQuestion: 'Can we separate authorised work from misuse without relying on intent?',
  },
  {
    id: 'collection',
    label: 'Collection',
    order: 4,
    intent: 'Sensitive records are located, aggregated, archived, or staged for movement.',
    defenderQuestion: 'Can we prove what data was gathered, and whether it was sensitive?',
  },
  {
    id: 'exfiltration',
    label: 'Exfiltration',
    order: 5,
    intent: 'Data crosses the boundary through email, web upload, removable media, external sharing, or an API.',
    defenderQuestion: 'Can we prove the channel, the volume, and the destination?',
  },
  {
    id: 'concealment',
    label: 'Concealment',
    order: 6,
    intent: 'Logs, sensors, retention, permissions, or ownership evidence are altered, disabled, or destroyed.',
    defenderQuestion: 'Would we know if the record of the attack were changed?',
  },
  {
    id: 'response',
    label: 'Response',
    order: 7,
    intent: 'The defender escalates, contains, preserves evidence, and closes the case with a named owner.',
    defenderQuestion: 'Is there a named owner, a timely containment action, and exportable evidence?',
  },
];

const internalPreResignationExfiltration: ThreatScenario = {
  id: 'internal-pre-resignation-exfiltration',
  kind: 'internal',
  title: 'Pre-resignation data theft',
  actor: 'Departing account manager with standing access to the CRM and a shared document library.',
  objective: 'Take customer records and pricing material out of the estate before the last working day.',
  summary:
    'The workforce event is known to HR before it is known to security. Access stays legitimate throughout, so every stage turns on whether the evidence separates ordinary work from collection and transfer.',
  themes: ['insider-misuse', 'data-exfiltration'],
  stages: [
    {
      stageId: 'preparation',
      action: {
        summary: 'Resignation submitted; access unchanged',
        detail: 'HR records a resignation with a four-week notice period. No security review is triggered and entitlements stay as they were.',
      },
      evidence: [
        { sourceId: 'hr-case', signal: 'Resignation date and notice window', requiredFields: ['user', 'status', 'effectiveDate', 'manager'], status: 'present' },
        { sourceId: 'siem-enrichment', signal: 'Approved workforce transition-window enrichment on the user entity', requiredFields: ['user', 'transitionType', 'effectiveFrom', 'effectiveTo', 'approvalId'], status: 'absent' },
      ],
      controls: [
        { id: 'joiner-mover-leaver', name: 'Joiner/mover/leaver review', effect: 'investigate', outcome: 'partial', confidence: 'medium', note: 'Runs at termination, not at notice. The highest-risk four weeks fall outside it.' },
      ],
      gaps: [
        {
          id: 'ins-exf-g1',
          type: 'telemetry',
          severity: 'high',
          confidence: 'high',
          statement: 'HR notice events are not delivered to the SIEM, so no approved transition window is attached to the user entity.',
          consequence: 'Later collection and transfer activity is triaged without the one piece of context that would raise its priority.',
        },
      ],
      remediation: [
        { id: 'ins-exf-r1', action: 'Feed notice-period status into user-entity enrichment under an approved, minimum-necessary HR data agreement.', owner: 'Internal scenario programme', targetDate: '2026-09-30', effort: 'medium', gapIds: ['ins-exf-g1'] },
      ],
    },
    {
      stageId: 'access',
      action: {
        summary: 'Normal sign-in from a managed laptop',
        detail: 'The user authenticates to the identity provider with MFA and opens the CRM. Nothing about the session is anomalous.',
        technique: 'T1078 Valid Accounts',
      },
      evidence: [
        { sourceId: 'idp-auth', signal: 'Interactive sign-in with MFA result and device', requiredFields: ['user', 'timestamp', 'result', 'deviceId', 'application'], status: 'present' },
        { sourceId: 'saas-audit', signal: 'CRM session start and application entitlements', requiredFields: ['user', 'application', 'sessionId', 'role'], status: 'present' },
      ],
      controls: [
        { id: 'ins-exf-c-mfa', name: 'Conditional access with MFA', effect: 'block', outcome: 'bypassed', confidence: 'high', note: 'Working as designed and irrelevant here: the account is the legitimate owner.' },
        { id: 'ins-exf-c-signin', name: 'Sign-in audit trail', effect: 'investigate', outcome: 'holds', confidence: 'high', note: 'Session can be reconstructed later with device and application context.' },
      ],
      gaps: [],
      remediation: [],
    },
    {
      stageId: 'misuse',
      action: {
        summary: 'Report builder used to widen a legitimate query',
        detail: 'The user runs saved CRM reports across accounts outside their book of business, staying under any per-request row limit.',
        technique: 'T1213 Data from Information Repositories',
      },
      evidence: [
        { sourceId: 'saas-audit', signal: 'Report execution with row count and record scope', requiredFields: ['user', 'reportId', 'recordCount', 'objectType'], status: 'partial' },
        { sourceId: 'file-access', signal: 'Peer-group baseline for record access volume', requiredFields: ['actor', 'peerGroup', 'deviationScore'], status: 'absent' },
      ],
      controls: [
        { id: 'ins-exf-c-baseline', name: 'Peer-group access baseline', effect: 'detect', outcome: 'bypassed', confidence: 'low', note: 'Not built for CRM report objects, so a widened query looks like ordinary reporting.' },
      ],
      gaps: [
        {
          id: 'ins-exf-g2',
          type: 'detection',
          severity: 'high',
          confidence: 'medium',
          statement: 'CRM report events are collected but no tested analytic compares record scope to the user\'s own book of business.',
          consequence: 'The widened query passes without a credible alert. Analysts can reconstruct it afterwards but nobody is told at the time.',
        },
      ],
      remediation: [
        { id: 'ins-exf-r2', action: 'Build and test an analytic on report record-scope versus assigned accounts, tuned against a known-good month.', owner: 'Detection engineering', targetDate: '2026-08-31', effort: 'medium', gapIds: ['ins-exf-g2'] },
      ],
    },
    {
      stageId: 'collection',
      action: {
        summary: 'Exports staged into a personal folder and archived',
        detail: 'Report output is exported to CSV, moved into a local folder, and compressed into a single archive over several evenings.',
        technique: 'T1560 Archive Collected Data',
      },
      evidence: [
        { sourceId: 'saas-audit', signal: 'Export/download events with object and byte counts', requiredFields: ['user', 'action', 'objectId', 'bytes'], status: 'present' },
        { sourceId: 'endpoint-edr', signal: 'Archive creation and process lineage', requiredFields: ['host', 'user', 'process', 'commandLine', 'filePath'], status: 'present' },
        { sourceId: 'dlp', signal: 'Sensitive-type match on exported content', requiredFields: ['policy', 'sensitiveType', 'channel', 'action'], status: 'partial' },
      ],
      controls: [
        { id: 'ins-exf-c-edr', name: 'Endpoint archive telemetry', effect: 'detect', outcome: 'holds', confidence: 'high', note: 'Archive creation is recorded with parent process and file path.' },
        { id: 'ins-exf-c-dlp-endpoint', name: 'Endpoint DLP inspection', effect: 'detect', outcome: 'partial', confidence: 'medium', note: 'Inspects the email channel only. Local archive staging is outside policy scope.' },
      ],
      gaps: [
        {
          id: 'ins-exf-g3',
          type: 'detection',
          severity: 'critical',
          confidence: 'high',
          statement: 'Bulk export followed by local archive creation is visible in two sources but is never correlated into one alert.',
          consequence: 'Both halves of the collection story exist in the SIEM and neither raises anything on its own.',
        },
      ],
      remediation: [
        { id: 'ins-exf-r3', action: 'Correlate SaaS bulk export with endpoint archive creation for the same user inside a bounded time window.', owner: 'Detection engineering', targetDate: '2026-08-15', effort: 'medium', gapIds: ['ins-exf-g3'] },
      ],
    },
    {
      stageId: 'exfiltration',
      action: {
        summary: 'Archive uploaded to a personal cloud drive',
        detail: 'The archive is uploaded from the managed laptop to a consumer file-sharing domain over HTTPS in a single session.',
        technique: 'T1567.002 Exfiltration to Cloud Storage',
      },
      evidence: [
        { sourceId: 'proxy-dns', signal: 'Outbound upload volume with user and destination category', requiredFields: ['user', 'host', 'domain', 'bytesOut', 'action'], status: 'partial' },
        { sourceId: 'endpoint-edr', signal: 'Browser upload with originating file path', requiredFields: ['host', 'user', 'process', 'filePath', 'bytes'], status: 'present' },
      ],
      controls: [
        { id: 'ins-exf-c-proxy', name: 'Web category blocking', effect: 'block', outcome: 'bypassed', confidence: 'medium', note: 'Consumer file sharing is allowed by policy because several teams depend on it.' },
        { id: 'ins-exf-c-egress', name: 'Egress upload-volume alerting', effect: 'detect', outcome: 'partial', confidence: 'low', note: 'Fires on volume but cannot attribute the session to a user on shared egress addresses.' },
      ],
      gaps: [
        {
          id: 'ins-exf-g4',
          type: 'telemetry',
          severity: 'critical',
          confidence: 'high',
          statement: 'Proxy records the upload but shared network address translation strips the user identity, so egress volume cannot be attributed.',
          consequence: 'The single most important stage of the chain is an unlit zone: the transfer is visible, the person is not.',
        },
      ],
      remediation: [
        { id: 'ins-exf-r4', action: 'Restore user/device attribution on the egress path before tuning any upload-volume analytic.', owner: 'Network security', targetDate: '2026-10-31', effort: 'high', gapIds: ['ins-exf-g4'] },
      ],
    },
    {
      stageId: 'concealment',
      action: {
        summary: 'Local archive and browser history cleared',
        detail: 'The staged archive is deleted and browsing history is cleared. Endpoint telemetry has already been forwarded off the host.',
        technique: 'T1070 Indicator Removal',
      },
      evidence: [
        { sourceId: 'endpoint-edr', signal: 'File deletion and history clearing with process lineage', requiredFields: ['host', 'user', 'operation', 'filePath', 'process'], status: 'present' },
        { sourceId: 'siem-enrichment', signal: 'Forwarded-event integrity and ingestion freshness', requiredFields: ['source', 'lastSeen', 'volumeDelta'], status: 'present' },
      ],
      controls: [
        { id: 'ins-exf-c-forward', name: 'Off-host log forwarding', effect: 'investigate', outcome: 'holds', confidence: 'high', note: 'Deletion on the endpoint does not remove the forwarded record.' },
        { id: 'ins-exf-c-tamper', name: 'Sensor tamper alerting', effect: 'detect', outcome: 'holds', confidence: 'medium', note: 'No tamper occurred; the actor had no need to disable the sensor.' },
      ],
      gaps: [],
      remediation: [],
    },
    {
      stageId: 'response',
      action: {
        summary: 'Case opened after the last working day',
        detail: 'A customer reports a competitive approach weeks later. The investigation reconstructs the chain from retained evidence.',
      },
      evidence: [
        { sourceId: 'saas-audit', signal: 'Ninety-day retained export history', requiredFields: ['user', 'action', 'objectId', 'timestamp'], status: 'present' },
        { sourceId: 'hr-case', signal: 'Case notes, approvals, and investigator access audit', requiredFields: ['caseId', 'approver', 'accessAudit'], status: 'present' },
      ],
      controls: [
        { id: 'ins-exf-c-case', name: 'Internal scenario case workflow', effect: 'investigate', outcome: 'holds', confidence: 'high', note: 'Evidence can be exported with chain-of-custody notes.' },
        { id: 'ins-exf-c-contain', name: 'Session and entitlement revocation', effect: 'contain', outcome: 'bypassed', confidence: 'low', note: 'Containment came after departure, which is too late to matter.' },
      ],
      gaps: [
        {
          id: 'ins-exf-g5',
          type: 'response',
          severity: 'high',
          confidence: 'high',
          statement: 'No owner is accountable for acting on collection signals during a notice period, so escalation waits for an external complaint.',
          consequence: 'The estate can reconstruct the theft but cannot contain it. Response is forensic rather than timely.',
        },
      ],
      remediation: [
        { id: 'ins-exf-r5', action: 'Name an escalation owner and a containment playbook for notice-period collection signals, with a defined time to first action.', owner: 'SOC manager', targetDate: '2026-08-31', effort: 'low', gapIds: ['ins-exf-g5'] },
      ],
    },
  ],
};

const internalPrivilegedSabotage: ThreatScenario = {
  id: 'internal-privileged-sabotage',
  kind: 'internal',
  title: 'Privileged sabotage during a change freeze',
  actor: 'Infrastructure engineer holding standing administrative rights to a production platform.',
  objective: 'Delete production configuration and disrupt a service during a period when change is supposed to be frozen.',
  summary:
    'Privilege is real and approved. The question is not whether the actor could act, but whether the estate can tie each privileged action to an approval and stop it before impact lands.',
  themes: ['insider-misuse', 'privileged-admin', 'sabotage', 'detection-response'],
  stages: [
    {
      stageId: 'preparation',
      action: {
        summary: 'Standing admin rights retained after a role change',
        detail: 'A platform role granted for a prior project is never revoked. Entitlement review is annual and this account was last certified ten months ago.',
      },
      evidence: [
        { sourceId: 'privileged-admin', signal: 'Standing role assignment with grant date and approver', requiredFields: ['actor', 'role', 'grantedAt', 'approver'], status: 'present' },
        { sourceId: 'idp-auth', signal: 'Directory role membership change history', requiredFields: ['actor', 'targetUser', 'groupOrRole', 'action'], status: 'present' },
      ],
      controls: [
        { id: 'ins-sab-c-recert', name: 'Annual entitlement recertification', effect: 'investigate', outcome: 'partial', confidence: 'low', note: 'A twelve-month cycle cannot catch a role that became inappropriate in month two.' },
      ],
      gaps: [
        {
          id: 'ins-sab-g1',
          type: 'accepted-risk',
          severity: 'medium',
          confidence: 'high',
          statement: 'Standing administrative access is retained instead of moving to just-in-time elevation. The platform team accepted this to protect out-of-hours recovery times.',
          consequence: 'Recorded as a decision with a named owner. It stays visible as a gap and contributes no coverage.',
        },
      ],
      remediation: [],
    },
    {
      stageId: 'access',
      action: {
        summary: 'Vault checkout outside the approved window',
        detail: 'The engineer checks out the privileged credential at 02:10 on a Sunday. No change ticket references the window.',
        technique: 'T1078.003 Local Accounts',
      },
      evidence: [
        { sourceId: 'privileged-admin', signal: 'Vault checkout with session recording reference', requiredFields: ['actor', 'credentialId', 'sessionId', 'checkoutTime'], status: 'present' },
        { sourceId: 'siem-enrichment', signal: 'Change-window and ticket correlation on the privileged session', requiredFields: ['sessionId', 'ticketId', 'windowState'], status: 'present' },
      ],
      controls: [
        { id: 'ins-sab-c-window', name: 'Change-window correlation alert', effect: 'detect', outcome: 'holds', confidence: 'high', note: 'Privileged checkout with no matching approved ticket raises a tested alert within minutes.' },
        { id: 'ins-sab-c-vault', name: 'Credential vault approval gate', effect: 'delay', outcome: 'partial', confidence: 'medium', note: 'Break-glass path lets the checkout proceed while an approval request is pending.' },
      ],
      gaps: [],
      remediation: [],
    },
    {
      stageId: 'misuse',
      action: {
        summary: 'Destructive commands issued against production configuration',
        detail: 'Configuration objects are deleted through the platform command line inside a recorded privileged session.',
        technique: 'T1485 Data Destruction',
      },
      evidence: [
        { sourceId: 'privileged-admin', signal: 'Command and session recording with target objects', requiredFields: ['actor', 'sessionId', 'command', 'target'], status: 'present' },
        { sourceId: 'endpoint-edr', signal: 'Jump-host process lineage for the privileged session', requiredFields: ['host', 'user', 'process', 'commandLine'], status: 'present' },
      ],
      controls: [
        { id: 'ins-sab-c-freeze', name: 'Change-freeze command guard', effect: 'block', outcome: 'partial', confidence: 'medium', note: 'Blocks deployment pipelines but not direct platform commands.' },
        { id: 'ins-sab-c-session', name: 'Privileged session recording', effect: 'investigate', outcome: 'holds', confidence: 'high', note: 'Every command is attributable to a named human and a recorded session.' },
        { id: 'ins-sab-c-alert', name: 'Destructive-command analytic', effect: 'detect', outcome: 'holds', confidence: 'high', note: 'Delete operations on production configuration raise a high-severity alert.' },
      ],
      gaps: [],
      remediation: [],
    },
    {
      stageId: 'collection',
      actorPresent: false,
      action: {
        summary: 'No collection: the objective is disruption',
        detail: 'Nothing is gathered or staged. The estate proves the negative from object-level audit rather than assuming it.',
      },
      evidence: [
        { sourceId: 'cloud-storage', signal: 'Object read and export events on the affected platform', requiredFields: ['actor', 'object', 'action'], status: 'present' },
      ],
      controls: [
        { id: 'ins-sab-c-objaudit', name: 'Object-level audit trail', effect: 'investigate', outcome: 'holds', confidence: 'high', note: 'Confirms the negative: no bulk read preceded the deletions.' },
      ],
      gaps: [],
      remediation: [],
    },
    {
      stageId: 'exfiltration',
      actorPresent: false,
      action: {
        summary: 'No exfiltration path used',
        detail: 'No data leaves the boundary. Administrative hosts have no general egress path, so the stage is closed before the actor reaches it.',
      },
      evidence: [
        { sourceId: 'proxy-dns', signal: 'Outbound transfer volume for the jump host during the session', requiredFields: ['host', 'bytesOut', 'domain'], status: 'present' },
      ],
      controls: [
        { id: 'ins-sab-c-egress', name: 'Jump-host egress restriction', effect: 'block', outcome: 'holds', confidence: 'high', note: 'Administrative hosts have no general internet egress path. Nothing was attempted here, so nothing was stopped here.' },
      ],
      gaps: [],
      remediation: [],
    },
    {
      stageId: 'concealment',
      action: {
        summary: 'Platform audit log disabled mid-session',
        detail: 'The actor turns off the platform audit trail before the last deletions, then re-enables it.',
        technique: 'T1562.008 Disable or Modify Cloud Logs',
      },
      evidence: [
        { sourceId: 'privileged-admin', signal: 'Audit configuration change with actor and prior state', requiredFields: ['actor', 'setting', 'previousValue', 'newValue'], status: 'present' },
        { sourceId: 'siem-enrichment', signal: 'Ingestion volume drop and source freshness', requiredFields: ['source', 'lastSeen', 'volumeDelta'], status: 'partial' },
      ],
      controls: [
        { id: 'ins-sab-c-tamper', name: 'Audit-disable analytic', effect: 'detect', outcome: 'holds', confidence: 'high', note: 'The act of disabling the log is itself a logged, alerting event.' },
        { id: 'ins-sab-c-freshness', name: 'Ingestion freshness monitoring', effect: 'detect', outcome: 'partial', confidence: 'low', note: 'Volume-drop thresholds are set for daily trends, so a nine-minute blackout does not trip them.' },
      ],
      gaps: [
        {
          id: 'ins-sab-g2',
          type: 'detection',
          severity: 'medium',
          confidence: 'medium',
          statement: 'A short logging blackout is recorded but no analytic tests for gaps measured in minutes rather than days.',
          consequence: 'The tamper event alerts, but the blind window it created is never quantified during triage.',
        },
      ],
      remediation: [
        { id: 'ins-sab-r2', action: 'Add a short-window ingestion-gap analytic for privileged platforms and surface the blind interval on the alert.', owner: 'Detection engineering', targetDate: '2026-09-15', effort: 'medium', gapIds: ['ins-sab-g2'] },
      ],
    },
    {
      stageId: 'response',
      action: {
        summary: 'Session terminated and credential revoked within the hour',
        detail: 'The change-window alert and the destructive-command alert both page the on-call responder, who kills the session and revokes the credential.',
      },
      evidence: [
        { sourceId: 'privileged-admin', signal: 'Session termination and credential revocation record', requiredFields: ['sessionId', 'action', 'actor', 'timestamp'], status: 'present' },
        { sourceId: 'siem-enrichment', signal: 'Alert-to-containment timing for the incident', requiredFields: ['alertId', 'firstAction', 'containedAt'], status: 'present' },
      ],
      controls: [
        { id: 'ins-sab-c-oncall', name: 'On-call containment playbook', effect: 'contain', outcome: 'holds', confidence: 'high', note: 'Named owner, tested runbook, session killed and credential revoked inside the hour.' },
        { id: 'ins-sab-c-evidence', name: 'Evidence preservation and export', effect: 'investigate', outcome: 'holds', confidence: 'high', note: 'Session recording and command history exported with chain-of-custody notes.' },
      ],
      gaps: [],
      remediation: [],
    },
  ],
};

const cyberPhishingToRansomware: ThreatScenario = {
  id: 'cyber-phishing-to-ransomware',
  kind: 'cyber',
  title: 'External phishing to ransomware staging',
  actor: 'External access broker selling a foothold to a ransomware affiliate.',
  objective: 'Convert one stolen session into estate-wide encryption, after first destroying the backups.',
  summary:
    'An external chain that reaches deep because the identity layer is strong and the endpoint layer is not. Two stages hold; the middle of the chain is an unlit zone.',
  themes: ['credential-misuse', 'ransomware', 'detection-response'],
  stages: [
    {
      stageId: 'preparation',
      action: {
        summary: 'Look-alike domain registered and mailbox rules pre-tested',
        detail: 'The actor registers a domain resembling a supplier and sends a benign message first to confirm delivery.',
        technique: 'T1583.001 Acquire Infrastructure: Domains',
      },
      evidence: [
        { sourceId: 'email', signal: 'Inbound message with newly observed sender domain', requiredFields: ['sender', 'recipient', 'messageId', 'destinationDomain'], status: 'present' },
        { sourceId: 'proxy-dns', signal: 'First resolution of a newly registered domain', requiredFields: ['host', 'domain', 'queryTime', 'category'], status: 'partial' },
      ],
      controls: [
        { id: 'cyb-ran-c-mailfilter', name: 'Mail gateway reputation filtering', effect: 'block', outcome: 'bypassed', confidence: 'medium', note: 'The domain is too new and too clean to carry a bad reputation yet.' },
        { id: 'cyb-ran-c-newdomain', name: 'Newly observed domain alerting', effect: 'detect', outcome: 'partial', confidence: 'low', note: 'Fires often enough to be routinely suppressed by triage.' },
      ],
      gaps: [
        {
          id: 'cyb-ran-g1',
          type: 'accepted-risk',
          severity: 'low',
          confidence: 'high',
          statement: 'Newly registered domain alerts are suppressed at triage because the volume is not workable at current staffing.',
          consequence: 'Recorded as a decision with a named owner. It stays visible as a gap and contributes no coverage.',
        },
      ],
      remediation: [],
    },
    {
      stageId: 'access',
      action: {
        summary: 'Session cookie stolen through an adversary-in-the-middle page',
        detail: 'The user completes a genuine MFA challenge on a proxied sign-in page. The actor replays the resulting session cookie.',
        technique: 'T1557 Adversary-in-the-Middle',
      },
      evidence: [
        { sourceId: 'idp-auth', signal: 'Sign-in with satisfied MFA from an unfamiliar address and unmanaged device', requiredFields: ['user', 'result', 'sourceIp', 'deviceId', 'sessionId'], status: 'present' },
        { sourceId: 'idp-auth', signal: 'Token issuance and refresh trail', requiredFields: ['user', 'tokenId', 'issuedAt', 'clientApp'], status: 'present' },
        { sourceId: 'siem-enrichment', signal: 'Impossible-travel and device-trust enrichment', requiredFields: ['user', 'geo', 'deviceTrust'], status: 'present' },
      ],
      controls: [
        { id: 'cyb-ran-c-ca', name: 'Device-bound conditional access', effect: 'block', outcome: 'partial', confidence: 'high', note: 'Holds for administrative applications. Standard applications accept the replayed cookie, and the actor only needs one of those.' },
        { id: 'cyb-ran-c-riskysignin', name: 'Risky sign-in analytic', effect: 'detect', outcome: 'holds', confidence: 'high', note: 'Satisfied MFA from a new device and country raises a tested alert.' },
        { id: 'cyb-ran-c-revoke', name: 'Automatic token revocation', effect: 'contain', outcome: 'partial', confidence: 'medium', note: 'Revokes on confirmed risk, but a human confirmation step sits in the path.' },
      ],
      gaps: [],
      remediation: [],
    },
    {
      stageId: 'misuse',
      action: {
        summary: 'Remote management tool installed on an unmanaged contractor host',
        detail: 'The replayed session reaches a standard application, from which the actor pivots to a contractor laptop with no endpoint agent.',
        technique: 'T1219 Remote Access Software',
      },
      evidence: [
        { sourceId: 'endpoint-edr', signal: 'Process and installer lineage on the contractor host', requiredFields: ['host', 'user', 'process', 'parentProcess', 'commandLine'], status: 'absent' },
        { sourceId: 'proxy-dns', signal: 'Outbound connection to a remote-management service', requiredFields: ['host', 'domain', 'category', 'action'], status: 'partial' },
      ],
      controls: [
        { id: 'cyb-ran-c-edr', name: 'Endpoint detection and response agent', effect: 'detect', outcome: 'bypassed', confidence: 'high', note: 'Not deployed to contractor-owned devices, which are a permitted part of the operating model.' },
        { id: 'cyb-ran-c-appctl', name: 'Application control', effect: 'block', outcome: 'bypassed', confidence: 'high', note: 'Enforced on managed devices only.' },
      ],
      gaps: [
        {
          id: 'cyb-ran-g2',
          type: 'telemetry',
          severity: 'critical',
          confidence: 'high',
          statement: 'Contractor-owned hosts carry no endpoint sensor, so process execution on them is not recorded anywhere.',
          consequence: 'The pivot host is an unlit zone. Nothing the actor does on it can be seen, alerted on, or reconstructed.',
        },
      ],
      remediation: [
        { id: 'cyb-ran-r2', action: 'Require an endpoint sensor or a brokered virtual desktop for contractor access to internal systems; treat unmanaged devices as untrusted at the network layer.', owner: 'Endpoint security', targetDate: '2026-11-30', effort: 'high', gapIds: ['cyb-ran-g2'] },
      ],
    },
    {
      stageId: 'collection',
      action: {
        summary: 'Domain and backup infrastructure enumerated',
        detail: 'From the unmonitored host the actor enumerates directory objects, locates the backup platform, and harvests a service-account credential.',
        technique: 'T1087 Account Discovery',
      },
      evidence: [
        { sourceId: 'idp-auth', signal: 'Directory enumeration queries by account and volume', requiredFields: ['actor', 'queryType', 'objectCount', 'sourceIp'], status: 'partial' },
        { sourceId: 'privileged-admin', signal: 'Service-account authentication from an unexpected source', requiredFields: ['actor', 'sourceIp', 'result', 'target'], status: 'present' },
      ],
      controls: [
        { id: 'cyb-ran-c-enum', name: 'Directory enumeration analytic', effect: 'detect', outcome: 'bypassed', confidence: 'low', note: 'Written against endpoint telemetry that does not exist for this host.' },
        { id: 'cyb-ran-c-svcacct', name: 'Service-account source restriction', effect: 'block', outcome: 'bypassed', confidence: 'medium', note: 'The backup service account is permitted to authenticate from any internal address.' },
      ],
      gaps: [
        {
          id: 'cyb-ran-g3',
          type: 'detection',
          severity: 'critical',
          confidence: 'high',
          statement: 'Service-account authentication from an unusual source is logged in the identity provider but no analytic tests for it.',
          consequence: 'The activity passes without a credible alert even though the evidence needed to catch it was collected.',
        },
      ],
      remediation: [
        { id: 'cyb-ran-r3', action: 'Alert on backup and infrastructure service accounts authenticating outside their declared source ranges, then restrict those ranges.', owner: 'Detection engineering', targetDate: '2026-08-31', effort: 'low', gapIds: ['cyb-ran-g3'] },
      ],
    },
    {
      stageId: 'exfiltration',
      action: {
        summary: 'Sample data staged and uploaded ahead of encryption',
        detail: 'A representative slice of file-share content is compressed and pushed to external storage to support a leak threat.',
        technique: 'T1567 Exfiltration Over Web Service',
      },
      evidence: [
        { sourceId: 'proxy-dns', signal: 'Sustained outbound upload volume to external storage', requiredFields: ['host', 'domain', 'bytesOut', 'action'], status: 'present' },
        { sourceId: 'file-access', signal: 'Bulk read across file-share objects', requiredFields: ['actor', 'object', 'action', 'bytes'], status: 'present' },
        { sourceId: 'dlp', signal: 'Sensitive-type match on the transferred content', requiredFields: ['policy', 'sensitiveType', 'channel', 'action'], status: 'absent' },
      ],
      controls: [
        { id: 'cyb-ran-c-uploadvol', name: 'Upload-volume analytic', effect: 'detect', outcome: 'holds', confidence: 'medium', note: 'A sustained multi-gigabyte upload to external storage raises an alert.' },
        { id: 'cyb-ran-c-dlpweb', name: 'Web-channel DLP inspection', effect: 'block', outcome: 'bypassed', confidence: 'high', note: 'DLP is enforced on email only. The web channel is not inspected.' },
      ],
      gaps: [
        {
          id: 'cyb-ran-g4',
          type: 'telemetry',
          severity: 'high',
          confidence: 'high',
          statement: 'The web channel carries no data-classification inspection, so the alert says how much left but not what left.',
          consequence: 'Responders can prove a large transfer occurred and cannot state whether regulated data was in it.',
        },
      ],
      remediation: [
        { id: 'cyb-ran-r4', action: 'Extend data-classification inspection to the web upload channel and record the disposition on each event.', owner: 'Data protection engineering', targetDate: '2026-10-15', effort: 'high', gapIds: ['cyb-ran-g4'] },
      ],
    },
    {
      stageId: 'concealment',
      action: {
        summary: 'Backup catalogue deleted before encryption begins',
        detail: 'The harvested service account deletes retention policies and the backup catalogue, then encryption is launched estate-wide.',
        technique: 'T1490 Inhibit System Recovery',
      },
      evidence: [
        { sourceId: 'privileged-admin', signal: 'Backup policy and catalogue deletion with actor', requiredFields: ['actor', 'action', 'target', 'timestamp'], status: 'present' },
        { sourceId: 'cloud-storage', signal: 'Immutable-store lock state and object deletion attempts', requiredFields: ['actor', 'object', 'action', 'lockState'], status: 'present' },
      ],
      controls: [
        { id: 'cyb-ran-c-immutable', name: 'Immutable backup retention lock', effect: 'block', outcome: 'holds', confidence: 'high', note: 'Locked objects cannot be deleted by any credential, including the one the actor holds. Recovery survives.' },
        { id: 'cyb-ran-c-backupalert', name: 'Backup-deletion analytic', effect: 'detect', outcome: 'holds', confidence: 'high', note: 'Deletion attempts against retention policy raise a critical alert.' },
        { id: 'cyb-ran-c-isolate', name: 'Automated host isolation', effect: 'contain', outcome: 'holds', confidence: 'high', note: 'The critical alert triggers network isolation of the source and disables the service account.' },
      ],
      gaps: [],
      remediation: [],
    },
    {
      stageId: 'response',
      action: {
        summary: 'Containment holds; recovery path is provable',
        detail: 'Encryption is stopped at the isolation boundary. Immutable copies are verified before restore begins.',
      },
      evidence: [
        { sourceId: 'siem-enrichment', signal: 'Alert-to-isolation timing and case linkage', requiredFields: ['alertId', 'containedAt', 'caseId'], status: 'present' },
        { sourceId: 'cloud-storage', signal: 'Restore-point verification record', requiredFields: ['object', 'lockState', 'verifiedAt'], status: 'present' },
      ],
      controls: [
        { id: 'cyb-ran-c-ir', name: 'Ransomware response playbook', effect: 'contain', outcome: 'holds', confidence: 'high', note: 'Named owner, tested restore path, verified immutable copies.' },
        { id: 'cyb-ran-c-forensics', name: 'Forensic evidence capture', effect: 'investigate', outcome: 'partial', confidence: 'low', note: 'The contractor pivot host holds no historical telemetry, so root-cause depth stops at the network edge.' },
      ],
      gaps: [
        {
          id: 'cyb-ran-g5',
          type: 'response',
          severity: 'medium',
          confidence: 'medium',
          statement: 'Containment is fast, but the post-incident evidence needed to prove the initial pivot cannot be recovered from an unmanaged host.',
          consequence: 'The estate can stop the attack and cannot fully explain it, which weakens regulatory and contractual reporting.',
        },
      ],
      remediation: [
        { id: 'cyb-ran-r5', action: 'Define a minimum forensic-evidence standard for any device permitted to reach internal systems, and test it during the next exercise.', owner: 'SOC manager', targetDate: '2026-09-30', effort: 'medium', gapIds: ['cyb-ran-g5'] },
      ],
    },
  ],
};

const cyberSaasTokenTheft: ThreatScenario = {
  id: 'cyber-saas-token-theft',
  kind: 'cyber',
  title: 'Delegated application consent against a SaaS tenant',
  actor: 'External actor operating a malicious third-party application registration.',
  objective: 'Hold long-lived delegated access to mail and files without ever handling a password.',
  summary:
    'Nothing is compromised in the usual sense. A user grants consent, and the resulting token outlives every password reset the estate can perform.',
  themes: ['credential-misuse', 'cloud-saas', 'data-exfiltration', 'detection-response'],
  stages: [
    {
      stageId: 'preparation',
      action: {
        summary: 'Application registered with plausible branding and broad scopes',
        detail: 'The actor publishes an application requesting mail-read and file-read scopes, presented as a productivity add-in.',
        technique: 'T1585 Establish Accounts',
      },
      evidence: [
        { sourceId: 'idp-auth', signal: 'Service principal creation and requested scope set', requiredFields: ['appId', 'publisher', 'scope', 'createdAt'], status: 'present' },
      ],
      controls: [
        { id: 'cyb-oauth-c-verified', name: 'Verified-publisher requirement', effect: 'block', outcome: 'partial', confidence: 'medium', note: 'Applies to admin-consent flows. User-consent flows still accept unverified publishers.' },
      ],
      gaps: [],
      remediation: [],
    },
    {
      stageId: 'access',
      action: {
        summary: 'User grants delegated consent',
        detail: 'A user clicks through the consent prompt. No credential is stolen and no MFA challenge is bypassed.',
        technique: 'T1528 Steal Application Access Token',
      },
      evidence: [
        { sourceId: 'idp-auth', signal: 'Consent grant with actor, application, and scope', requiredFields: ['user', 'appId', 'scope', 'grantType'], status: 'present' },
        { sourceId: 'saas-audit', signal: 'First application access to mail and file objects', requiredFields: ['appId', 'user', 'objectType', 'action'], status: 'present' },
      ],
      controls: [
        { id: 'cyb-oauth-c-consentpolicy', name: 'User-consent restriction policy', effect: 'block', outcome: 'bypassed', confidence: 'high', note: 'Set to allow consent for low-risk scopes; mail-read is classified as low risk.' },
        { id: 'cyb-oauth-c-consentalert', name: 'Consent-grant analytic', effect: 'detect', outcome: 'holds', confidence: 'medium', note: 'Fires on consent to an unverified publisher, at informational severity.' },
      ],
      gaps: [
        {
          id: 'cyb-oauth-g1',
          type: 'response',
          severity: 'high',
          confidence: 'high',
          statement: 'The consent alert exists and is real, but it lands in a queue with no owner and no revocation runbook.',
          consequence: 'Activity is visible from the first minute and nothing is done about it for the life of the token.',
        },
      ],
      remediation: [
        { id: 'cyb-oauth-r1', action: 'Assign the consent-grant queue to a named owner with a revoke-and-notify runbook and a defined time to first action.', owner: 'Identity engineering', targetDate: '2026-08-15', effort: 'low', gapIds: ['cyb-oauth-g1'] },
      ],
    },
    {
      stageId: 'misuse',
      action: {
        summary: 'Application acts as the user, at machine speed',
        detail: 'The token is used from actor infrastructure to enumerate mailbox folders and file libraries continuously.',
        technique: 'T1114 Email Collection',
      },
      evidence: [
        { sourceId: 'saas-audit', signal: 'Application-identity access with client and source address', requiredFields: ['appId', 'user', 'sourceIp', 'userAgent', 'action'], status: 'present' },
        { sourceId: 'siem-enrichment', signal: 'Separation of user-initiated and application-initiated access', requiredFields: ['actorType', 'appId', 'user'], status: 'absent' },
      ],
      controls: [
        { id: 'cyb-oauth-c-ueba', name: 'User behaviour analytics', effect: 'detect', outcome: 'bypassed', confidence: 'low', note: 'Treats application activity as the consenting user, so machine-speed access reads as normal for that user.' },
      ],
      gaps: [
        {
          id: 'cyb-oauth-g2',
          type: 'telemetry',
          severity: 'high',
          confidence: 'high',
          statement: 'Application-initiated access is not distinguished from user-initiated access in the correlation layer.',
          consequence: 'Every downstream analytic is measuring the wrong actor. The delegated identity is an unlit zone inside a lit source.',
        },
      ],
      remediation: [
        { id: 'cyb-oauth-r2', action: 'Normalise an actor-type field across SaaS audit sources so application identities can be baselined separately from humans.', owner: 'Detection engineering', targetDate: '2026-09-30', effort: 'medium', gapIds: ['cyb-oauth-g2'] },
      ],
    },
    {
      stageId: 'collection',
      action: {
        summary: 'Mail and document libraries harvested through the API',
        detail: 'Message bodies, attachments, and shared documents are pulled steadily and slowly enough to avoid rate limits.',
        technique: 'T1213 Data from Information Repositories',
      },
      evidence: [
        { sourceId: 'saas-audit', signal: 'Per-object read events attributed to the application', requiredFields: ['appId', 'objectId', 'action', 'bytes'], status: 'present' },
        { sourceId: 'email', signal: 'Mailbox item access by delegated application', requiredFields: ['mailbox', 'appId', 'action', 'itemCount'], status: 'partial' },
      ],
      controls: [
        { id: 'cyb-oauth-c-ratelimit', name: 'Tenant API throttling', effect: 'delay', outcome: 'holds', confidence: 'medium', note: 'Slows harvesting to weeks rather than hours. It buys time; it does not stop anything.' },
        { id: 'cyb-oauth-c-mailaudit', name: 'Mailbox audit logging', effect: 'investigate', outcome: 'partial', confidence: 'medium', note: 'Item-level access is recorded for some mailbox types and not for others.' },
      ],
      gaps: [
        {
          id: 'cyb-oauth-g3',
          type: 'detection',
          severity: 'high',
          confidence: 'medium',
          statement: 'Steady low-rate API reads across many objects never cross the volume thresholds the analytics were written against.',
          consequence: 'The collection passes without a credible alert precisely because the throttling control worked.',
        },
      ],
      remediation: [
        { id: 'cyb-oauth-r3', action: 'Add a cumulative-read analytic per application identity over a rolling window rather than a per-hour volume threshold.', owner: 'Detection engineering', targetDate: '2026-10-31', effort: 'medium', gapIds: ['cyb-oauth-g3'] },
      ],
    },
    {
      stageId: 'exfiltration',
      action: {
        summary: 'Data leaves through the sanctioned API path',
        detail: 'There is no unusual channel. The transfer is the application doing exactly what consent permitted.',
        technique: 'T1567 Exfiltration Over Web Service',
      },
      evidence: [
        { sourceId: 'saas-audit', signal: 'Application read volume by source address and time', requiredFields: ['appId', 'sourceIp', 'bytes', 'timestamp'], status: 'present' },
        { sourceId: 'proxy-dns', signal: 'Corporate egress records for the transfer', requiredFields: ['host', 'domain', 'bytesOut'], status: 'absent' },
      ],
      controls: [
        { id: 'cyb-oauth-c-dlpapi', name: 'DLP inspection on the API channel', effect: 'detect', outcome: 'bypassed', confidence: 'high', note: 'DLP covers email, endpoint, and web. The delegated API channel is not inspected.' },
      ],
      gaps: [
        {
          id: 'cyb-oauth-g4',
          type: 'telemetry',
          severity: 'critical',
          confidence: 'high',
          statement: 'The transfer never touches the corporate network, so no egress or data-protection channel observes it. Only the SaaS provider records it.',
          consequence: 'Every network-side control is structurally blind here. Coverage claimed from network telemetry does not apply to this stage.',
        },
      ],
      remediation: [
        { id: 'cyb-oauth-r4', action: 'Treat the SaaS provider audit trail as a primary exfiltration source with its own retention and searchability requirement, not as supporting context.', owner: 'SaaS platform engineering', targetDate: '2026-09-30', effort: 'medium', gapIds: ['cyb-oauth-g4'] },
      ],
    },
    {
      stageId: 'concealment',
      action: {
        summary: 'Nothing is concealed because nothing looks wrong',
        detail: 'The actor changes no setting and deletes no log. The grant is a legitimate record in the tenant, and password resets do not disturb it.',
        technique: 'T1550.001 Application Access Token',
      },
      evidence: [
        { sourceId: 'idp-auth', signal: 'Standing consent grant and refresh-token lifetime', requiredFields: ['appId', 'grantId', 'refreshExpiry'], status: 'present' },
      ],
      controls: [
        { id: 'cyb-oauth-c-passwordreset', name: 'Credential reset on suspicion', effect: 'contain', outcome: 'bypassed', confidence: 'high', note: 'A password reset does not invalidate a delegated refresh token. The wrong control is being counted as containment.' },
      ],
      gaps: [
        {
          id: 'cyb-oauth-g5',
          type: 'detection',
          severity: 'medium',
          confidence: 'medium',
          statement: 'No analytic reviews standing consent grants for age, scope breadth, or continued business need.',
          consequence: 'The access persists indefinitely and nothing in the estate is looking for it.',
        },
      ],
      remediation: [
        { id: 'cyb-oauth-r5', action: 'Schedule a recurring review of delegated grants by scope breadth and last-used date, with automatic revocation of dormant grants.', owner: 'Identity engineering', targetDate: '2026-11-30', effort: 'low', gapIds: ['cyb-oauth-g5'] },
      ],
    },
    {
      stageId: 'response',
      action: {
        summary: 'Discovered by the provider, not by the estate',
        detail: 'The SaaS provider removes the malicious application from its marketplace and notifies affected tenants. Grants are revoked afterwards.',
      },
      evidence: [
        { sourceId: 'idp-auth', signal: 'Grant revocation and token invalidation record', requiredFields: ['appId', 'grantId', 'revokedAt', 'actor'], status: 'present' },
        { sourceId: 'saas-audit', signal: 'Historical application access for scoping the exposure', requiredFields: ['appId', 'objectId', 'action', 'timestamp'], status: 'partial' },
      ],
      controls: [
        { id: 'cyb-oauth-c-revoke', name: 'Grant revocation', effect: 'contain', outcome: 'holds', confidence: 'high', note: 'Effective once performed. The delay before performing it is the whole problem.' },
        { id: 'cyb-oauth-c-scope', name: 'Exposure scoping from provider audit', effect: 'investigate', outcome: 'partial', confidence: 'low', note: 'Audit retention is shorter than the life of the grant, so the earliest access cannot be enumerated.' },
      ],
      gaps: [
        {
          id: 'cyb-oauth-g6',
          type: 'response',
          severity: 'critical',
          confidence: 'high',
          statement: 'Detection came from a third party. The estate had the evidence from day one and no owner, threshold, or containment path attached to it.',
          consequence: 'Time to containment was set by someone else\'s process. Exposure scope cannot be fully established from retained evidence.',
        },
      ],
      remediation: [
        { id: 'cyb-oauth-r6', action: 'Extend SaaS audit retention to cover the maximum refresh-token lifetime, and rehearse grant revocation as a containment action.', owner: 'SaaS platform engineering', targetDate: '2026-10-31', effort: 'medium', gapIds: ['cyb-oauth-g6'] },
      ],
    },
  ],
};

interface CuratedStageSpec {
  action: string;
  detail: string;
  technique?: string;
  sourceId: LogSourceId;
  signal: string;
  evidenceStatus: EvidenceStatus;
  gapType?: GapType;
  severity?: Severity;
  controlEffect?: ControlEffect;
  controlOutcome?: ControlOutcome;
  actorPresent?: boolean;
}

interface CuratedScenarioSpec extends Omit<ThreatScenario, 'stages'> {
  stages: Record<AttackChainStageId, CuratedStageSpec>;
}

/**
 * Keeps additional workshop scenarios concise without weakening the canonical model: every
 * generated scenario still carries all seven stages, explicit evidence health, a named
 * control outcome, typed gaps, and linked remediation.
 */
function createCuratedScenario(spec: CuratedScenarioSpec): ThreatScenario {
  return {
    ...spec,
    stages: attackChainStages.map((stage): ScenarioStage => {
      const item = spec.stages[stage.id];
      const actorPresent = item.actorPresent ?? true;
      const gapId = `${spec.id}-${stage.id}-gap`;
      const gap = item.gapType
        ? {
            id: gapId,
            type: item.gapType,
            severity: item.severity ?? 'high',
            confidence: 'high' as const,
            statement: `${item.signal} is not sufficiently ready for this stage.`,
            consequence: `The ${stage.label.toLowerCase()} activity may not be detected, explained, or contained with defensible evidence.`,
          }
        : null;
      const controlEffect = item.controlEffect ?? (stage.id === 'response' ? 'contain' : 'detect');
      const controlOutcome = item.controlOutcome ?? (gap ? 'partial' : 'holds');

      return {
        stageId: stage.id,
        actorPresent,
        action: { summary: item.action, detail: item.detail, technique: item.technique },
        evidence: actorPresent
          ? [{ sourceId: item.sourceId, signal: item.signal, requiredFields: ['actor', 'target', 'timestamp', 'result'], status: item.evidenceStatus }]
          : [],
        controls: actorPresent
          ? [{
              id: `${spec.id}-${stage.id}-control`,
              name: `${stage.label} readiness control`,
              effect: controlEffect,
              outcome: controlOutcome,
              confidence: item.evidenceStatus === 'present' ? 'high' : 'medium',
              note: gap ? 'The control exists but its evidence or operating path is incomplete.' : 'The control has usable evidence and a defined operating path.',
            }]
          : [],
        gaps: gap ? [gap] : [],
        remediation:
          gap && gap.type !== 'accepted-risk'
            ? [{
                id: `${spec.id}-${stage.id}-remediation`,
                action: `Close the ${gap.type} gap for ${item.signal.toLowerCase()} and validate the result in a scenario exercise.`,
                owner: gap.type === 'response' ? 'Incident response' : 'Detection engineering',
                targetDate: '2026-12-15',
                effort: 'medium',
                gapIds: [gapId],
              }]
            : [],
      };
    }),
  };
}

const thirdPartyCloudExport = createCuratedScenario({
  id: 'third-party-cloud-export',
  kind: 'internal',
  title: 'Contractor cloud export after engagement end',
  actor: 'Third-party specialist whose federated account and project workspace remain active after the engagement ends.',
  objective: 'Export project data through an approved SaaS interface after the contractual access window closes.',
  summary: 'This scenario tests third-party lifecycle ownership, federated identity correlation, SaaS export fidelity, external sharing, and timely containment.',
  themes: ['third-party', 'credential-misuse', 'cloud-saas', 'data-exfiltration', 'detection-response'],
  stages: {
    preparation: { action: 'Engagement ends without an access trigger', detail: 'The supplier record closes, but no identity workflow receives the effective end date.', sourceId: 'hr-case', signal: 'Third-party end date and sponsor', evidenceStatus: 'absent', gapType: 'telemetry' },
    access: { action: 'Federated account starts a new session', detail: 'The external identity still satisfies the application access policy.', technique: 'T1078 Valid Accounts', sourceId: 'idp-auth', signal: 'Federated sign-in, sponsor, and device context', evidenceStatus: 'present' },
    misuse: { action: 'Project permissions are used outside the agreed window', detail: 'Valid workspace access is used after the approved delivery period.', sourceId: 'saas-audit', signal: 'Workspace role and object access', evidenceStatus: 'partial', gapType: 'detection' },
    collection: { action: 'Workspace records are exported in bulk', detail: 'The actor uses a native bulk export that resembles ordinary project closeout.', technique: 'T1213 Data from Information Repositories', sourceId: 'saas-audit', signal: 'Bulk export with object and byte counts', evidenceStatus: 'present' },
    exfiltration: { action: 'Export is shared to an external cloud account', detail: 'A public-safe sharing feature moves the archive outside the managed workspace.', technique: 'T1567.002 Exfiltration to Cloud Storage', sourceId: 'cloud-storage', signal: 'External share destination and object classification', evidenceStatus: 'partial', gapType: 'detection' },
    concealment: { action: 'Workspace membership is removed', detail: 'The actor removes their visible workspace membership after the export.', sourceId: 'saas-audit', signal: 'Membership and permission change history', evidenceStatus: 'present' },
    response: { action: 'Sponsor and security teams coordinate revocation', detail: 'Identity, SaaS sessions, and external links must be revoked under one owner.', sourceId: 'siem-enrichment', signal: 'Case ownership and revocation evidence', evidenceStatus: 'partial', gapType: 'response', controlEffect: 'contain' },
  },
});

const breakGlassCredentialMisuse = createCuratedScenario({
  id: 'break-glass-credential-misuse',
  kind: 'internal',
  title: 'Emergency administrator credential misuse',
  actor: 'Operator using a shared emergency credential without a corresponding incident or approved change.',
  objective: 'Change production access controls and weaken recovery safeguards outside change control.',
  summary: 'This scenario separates emergency access from approved work and tests vault attribution, command evidence, change correlation, sabotage detection, and recovery ownership.',
  themes: ['insider-misuse', 'privileged-admin', 'credential-misuse', 'sabotage', 'detection-response'],
  stages: {
    preparation: { action: 'Emergency credential is checked out without a ticket', detail: 'The vault permits access using a generic justification.', sourceId: 'privileged-admin', signal: 'Vault checkout, approver, and ticket reference', evidenceStatus: 'partial', gapType: 'detection' },
    access: { action: 'Shared administrator session reaches production', detail: 'The target records the emergency identity but not the human operator.', technique: 'T1078 Valid Accounts', sourceId: 'privileged-admin', signal: 'Human-to-shared-account session attribution', evidenceStatus: 'absent', gapType: 'telemetry' },
    misuse: { action: 'Access policy and recovery settings are changed', detail: 'The session expands privilege and reduces recovery safeguards.', technique: 'T1098 Account Manipulation', sourceId: 'privileged-admin', signal: 'Privileged commands and before/after configuration', evidenceStatus: 'present' },
    collection: { action: 'Configuration and secrets inventory is queried', detail: 'The session enumerates service identities and recovery material.', sourceId: 'cloud-storage', signal: 'Sensitive configuration reads', evidenceStatus: 'partial', gapType: 'detection' },
    exfiltration: { action: 'No data-transfer action is modelled', detail: 'The objective is sabotage and persistence, not data movement.', sourceId: 'proxy-dns', signal: 'Outbound transfer evidence', evidenceStatus: 'present', actorPresent: false },
    concealment: { action: 'Audit retention is shortened', detail: 'The same session changes the evidence window before ending.', technique: 'T1562.001 Impair Defenses: Disable or Modify Tools', sourceId: 'siem-enrichment', signal: 'Retention and source-health change alert', evidenceStatus: 'partial', gapType: 'detection' },
    response: { action: 'Emergency access is rotated and changes are restored', detail: 'Containment requires credential rotation, configuration recovery, and accountable review.', sourceId: 'privileged-admin', signal: 'Credential rotation and recovery validation', evidenceStatus: 'partial', gapType: 'response', controlEffect: 'contain' },
  },
});

const detectionPipelineSuppression = createCuratedScenario({
  id: 'detection-pipeline-suppression',
  kind: 'cyber',
  title: 'Staged attacker suppresses cloud detection coverage',
  actor: 'External actor using a compromised automation identity with permission to change cloud logging and alert routing.',
  objective: 'Create a quiet window for destructive changes by suppressing audit delivery and response notifications.',
  summary: 'This scenario focuses on SOC engineering controls: service-identity use, logging health, analytic dependencies, alert routing, independent evidence, and restoration testing.',
  themes: ['credential-misuse', 'cloud-saas', 'sabotage', 'ransomware', 'detection-response'],
  stages: {
    preparation: { action: 'Automation credential is recovered from a stale deployment', detail: 'A long-lived secret remains usable after the deployment is retired.', technique: 'T1552.001 Unsecured Credentials: Credentials In Files', sourceId: 'cloud-storage', signal: 'Service credential age and last use', evidenceStatus: 'partial', gapType: 'detection' },
    access: { action: 'Automation identity calls cloud administration APIs', detail: 'Non-interactive access originates from a new client and network.', technique: 'T1078.004 Valid Accounts: Cloud Accounts', sourceId: 'idp-auth', signal: 'Workload identity, client, and source network', evidenceStatus: 'present' },
    misuse: { action: 'Audit export and alert routes are changed', detail: 'The actor disables one sink and redirects operational notifications.', technique: 'T1562.008 Impair Defenses: Disable or Modify Cloud Logs', sourceId: 'saas-audit', signal: 'Audit configuration and alert-route changes', evidenceStatus: 'partial', gapType: 'detection' },
    collection: { action: 'Recovery resources and critical services are enumerated', detail: 'The actor maps backup locations and systems needed for restoration.', technique: 'T1526 Cloud Service Discovery', sourceId: 'cloud-storage', signal: 'Recovery-resource listing and access', evidenceStatus: 'present' },
    exfiltration: { action: 'No data-transfer action is modelled', detail: 'The objective is a quiet impact window, not data theft.', sourceId: 'proxy-dns', signal: 'Outbound transfer evidence', evidenceStatus: 'present', actorPresent: false },
    concealment: { action: 'Telemetry delivery drops below its normal baseline', detail: 'Events exist at the source but stop reaching the detection platform.', technique: 'T1562.008 Impair Defenses: Disable or Modify Cloud Logs', sourceId: 'siem-enrichment', signal: 'Source freshness, volume, and parser health', evidenceStatus: 'absent', gapType: 'telemetry' },
    response: { action: 'Independent health alert triggers restoration', detail: 'Responders must restore logging, revoke the identity, and verify missed detections.', sourceId: 'siem-enrichment', signal: 'Independent pipeline-health alert and response runbook', evidenceStatus: 'partial', gapType: 'response', controlEffect: 'contain' },
  },
});

const negligentExternalSharing = createCuratedScenario({
  id: 'negligent-external-sharing',
  kind: 'internal',
  title: 'Accidental external sharing',
  actor: 'Employee sharing a sensitive document with the wrong external recipient while completing normal work.',
  objective: 'Confirm what was exposed, who received it, and whether access was revoked without treating a mistake as malicious intent.',
  summary: 'A non-malicious insider scenario for testing sharing audit, data classification, DLP disposition, privacy-aware triage, and fast revocation.',
  themes: ['insider-misuse', 'data-exfiltration', 'cloud-saas', 'detection-response'],
  stages: {
    preparation: { action: 'Sensitive file is prepared for a legitimate task', detail: 'A project document is ready to share with an approved partner.', sourceId: 'file-access', signal: 'File owner, classification, and approved audience', evidenceStatus: 'partial', gapType: 'telemetry' },
    access: { action: 'User opens the document from a normal session', detail: 'Identity and device checks pass; there is no account compromise signal.', sourceId: 'idp-auth', signal: 'Authenticated user, device, and application session', evidenceStatus: 'present' },
    misuse: { action: 'The wrong external address is selected', detail: 'Autocomplete resolves to a similarly named contact outside the approved organisation.', sourceId: 'email', signal: 'Recipient, message, and attachment metadata', evidenceStatus: 'present' },
    collection: { action: 'Sensitive document is attached', detail: 'The file is attached without changing its classification.', sourceId: 'dlp', signal: 'Sensitive-data match and policy decision', evidenceStatus: 'partial', gapType: 'detection' },
    exfiltration: { action: 'Message is delivered externally', detail: 'The recipient opens the attachment before the sender notices the mistake.', sourceId: 'email', signal: 'Delivery, recipient, and message trace', evidenceStatus: 'present' },
    concealment: { action: 'No concealment is attempted', detail: 'The sender reports the mistake immediately.', sourceId: 'hr-case', signal: 'Self-reported incident timeline', evidenceStatus: 'present', actorPresent: false },
    response: { action: 'Access is revoked and exposure is scoped', detail: 'The team recalls the message where possible, revokes links, and records the recipient response.', sourceId: 'saas-audit', signal: 'Recall, link revocation, and case closure evidence', evidenceStatus: 'partial', gapType: 'response', controlEffect: 'contain' },
  },
});

const removableMediaTheft = createCuratedScenario({
  id: 'removable-media-data-theft',
  kind: 'internal',
  title: 'USB data theft',
  actor: 'Employee with legitimate access copying sensitive files to removable media outside their duties.',
  objective: 'Tie sensitive file access and USB copy activity to a person, device, and business context.',
  summary: 'Tests endpoint device control, object-level file audit, classification, copy-volume detection, and evidence preservation for removable-media exfiltration.',
  themes: ['insider-misuse', 'data-exfiltration', 'detection-response'],
  stages: {
    preparation: { action: 'Personal USB device is connected', detail: 'An unapproved removable device is attached to a managed endpoint.', technique: 'T1052.001 Exfiltration Over Physical Medium: Exfiltration over USB', sourceId: 'endpoint-edr', signal: 'USB device identity and connection event', evidenceStatus: 'present' },
    access: { action: 'User accesses a restricted project folder', detail: 'Valid credentials and standing file permissions are used.', technique: 'T1078 Valid Accounts', sourceId: 'file-access', signal: 'User, file path, classification, and access time', evidenceStatus: 'present' },
    misuse: { action: 'Access expands beyond normal project work', detail: 'The user reads folders outside their current assignment.', technique: 'T1213 Data from Information Repositories', sourceId: 'file-access', signal: 'Role and peer baseline for sensitive reads', evidenceStatus: 'partial', gapType: 'detection' },
    collection: { action: 'Files are staged into one folder', detail: 'Sensitive documents are gathered before transfer.', technique: 'T1074 Data Staged', sourceId: 'endpoint-edr', signal: 'File staging and copy sequence', evidenceStatus: 'present' },
    exfiltration: { action: 'Files are copied to USB', detail: 'The staged folder is written to removable media.', technique: 'T1052.001 Exfiltration Over Physical Medium: Exfiltration over USB', sourceId: 'endpoint-edr', signal: 'Source paths, device ID, bytes, and copy result', evidenceStatus: 'partial', gapType: 'telemetry', severity: 'critical' },
    concealment: { action: 'Staging folder is deleted', detail: 'Local copies are removed after the USB is disconnected.', technique: 'T1070 Indicator Removal', sourceId: 'endpoint-edr', signal: 'Deletion and process lineage', evidenceStatus: 'present' },
    response: { action: 'Device and account are contained', detail: 'The endpoint is isolated and the file set is reconstructed from audit data.', sourceId: 'siem-enrichment', signal: 'Case owner, containment time, and evidence export', evidenceStatus: 'partial', gapType: 'response', controlEffect: 'contain' },
  },
});

const businessRecordFraud = createCuratedScenario({
  id: 'business-record-fraud',
  kind: 'internal',
  title: 'Business record manipulation',
  actor: 'Employee altering customer, payment, payroll, or expense records for personal gain.',
  objective: 'Prove which records changed, who approved them, and whether segregation-of-duties controls worked.',
  summary: 'An insider-fraud scenario covering valid access, approval bypass, stored-data manipulation, audit integrity, and financial-impact scoping.',
  themes: ['insider-misuse', 'privileged-admin', 'sabotage', 'detection-response'],
  stages: {
    preparation: { action: 'Approval weakness is identified', detail: 'The actor learns that low-value changes receive little secondary review.', sourceId: 'saas-audit', signal: 'Approval workflow and role configuration', evidenceStatus: 'partial', gapType: 'detection' },
    access: { action: 'Normal business account signs in', detail: 'The user authenticates from a managed device during normal hours.', technique: 'T1078 Valid Accounts', sourceId: 'idp-auth', signal: 'User, device, session, and application', evidenceStatus: 'present' },
    misuse: { action: 'Payee or account details are changed', detail: 'A legitimate edit function is used outside the user’s authorised purpose.', technique: 'T1565.001 Data Manipulation: Stored Data Manipulation', sourceId: 'saas-audit', signal: 'Before/after values, actor, and target record', evidenceStatus: 'present' },
    collection: { action: 'High-value records are identified', detail: 'The actor searches for records likely to avoid routine review.', technique: 'T1213 Data from Information Repositories', sourceId: 'saas-audit', signal: 'Search, view, and report history', evidenceStatus: 'partial', gapType: 'detection' },
    exfiltration: { action: 'No data-transfer action is required', detail: 'The objective is manipulation inside the business system.', sourceId: 'proxy-dns', signal: 'Outbound transfer evidence', evidenceStatus: 'present', actorPresent: false },
    concealment: { action: 'Approval notes are edited after payment', detail: 'The actor changes supporting text to make the transaction appear routine.', technique: 'T1565.001 Data Manipulation: Stored Data Manipulation', sourceId: 'saas-audit', signal: 'Immutable change history and deleted notes', evidenceStatus: 'absent', gapType: 'telemetry', severity: 'critical' },
    response: { action: 'Records and approvals are reconstructed', detail: 'Fraud, finance, HR, and security teams preserve evidence under one case owner.', sourceId: 'hr-case', signal: 'Case approval, evidence access, and recovery record', evidenceStatus: 'partial', gapType: 'response', controlEffect: 'contain' },
  },
});

const insiderCollusion = createCuratedScenario({
  id: 'insider-collusion',
  kind: 'internal',
  title: 'Cross-user collusion',
  actor: 'Two employees in different roles coordinating access, approval, collection, and transfer.',
  objective: 'Reconstruct a multi-user timeline without assuming that each action is suspicious in isolation.',
  summary: 'Tests identity correlation, segregation of duties, shared-object history, approval evidence, and cross-user detection across normal-looking activity.',
  themes: ['insider-misuse', 'privileged-admin', 'data-exfiltration', 'detection-response'],
  stages: {
    preparation: { action: 'Users agree roles and timing', detail: 'One user can grant access; the other can export data.', sourceId: 'hr-case', signal: 'Role, reporting line, and approved case context', evidenceStatus: 'partial', gapType: 'telemetry' },
    access: { action: 'Access is granted through a valid workflow', detail: 'A user approves a temporary role for their collaborator.', technique: 'T1098 Account Manipulation', sourceId: 'idp-auth', signal: 'Granting actor, recipient, role, reason, and expiry', evidenceStatus: 'present' },
    misuse: { action: 'Temporary access is used outside its stated purpose', detail: 'The recipient searches sensitive records unrelated to the approved task.', technique: 'T1078 Valid Accounts', sourceId: 'saas-audit', signal: 'Session, role, object access, and stated purpose', evidenceStatus: 'partial', gapType: 'detection' },
    collection: { action: 'Records are exported in small batches', detail: 'Both users keep individual actions below volume thresholds.', technique: 'T1213 Data from Information Repositories', sourceId: 'file-access', signal: 'Cross-user object and export timeline', evidenceStatus: 'partial', gapType: 'detection' },
    exfiltration: { action: 'One user creates an external share', detail: 'The second user receives the data through a personal cloud account.', technique: 'T1567.002 Exfiltration to Cloud Storage', sourceId: 'cloud-storage', signal: 'Share creator, recipient, object, and destination', evidenceStatus: 'present' },
    concealment: { action: 'Temporary access is removed', detail: 'The original grant is revoked to make the sequence look complete.', technique: 'T1098 Account Manipulation', sourceId: 'idp-auth', signal: 'Full grant and revocation history', evidenceStatus: 'present' },
    response: { action: 'Multi-user evidence is preserved', detail: 'The investigation links actions by shared objects, timing, and approvals rather than a single alert.', sourceId: 'siem-enrichment', signal: 'Entity timeline, case owner, and corroboration record', evidenceStatus: 'partial', gapType: 'response', controlEffect: 'investigate' },
  },
});

const personalEmailForwarding = createCuratedScenario({
  id: 'personal-email-forwarding',
  kind: 'internal',
  title: 'Mailbox forwarding to a personal account',
  actor: 'Employee creating a forwarding rule or repeatedly sending sensitive attachments to personal email.',
  objective: 'Detect and scope mail leaving through forwarding rules, attachments, or delegated mailbox access.',
  summary: 'Tests mailbox audit, forwarding-rule detection, attachment metadata, DLP coverage, delegated access, and revocation of persistent mail flows.',
  themes: ['insider-misuse', 'data-exfiltration', 'cloud-saas', 'detection-response'],
  stages: {
    preparation: { action: 'Personal mailbox destination is tested', detail: 'A low-sensitivity message is sent externally before larger transfers begin.', technique: 'T1048 Exfiltration Over Alternative Protocol', sourceId: 'email', signal: 'External recipient and message trace', evidenceStatus: 'present' },
    access: { action: 'Mailbox opens through a normal session', detail: 'The legitimate user signs in from a known device.', technique: 'T1078 Valid Accounts', sourceId: 'idp-auth', signal: 'Mailbox session, user, device, and IP', evidenceStatus: 'present' },
    misuse: { action: 'External forwarding rule is created', detail: 'Selected messages are silently copied to a personal mailbox.', technique: 'T1114.003 Email Collection: Email Forwarding Rule', sourceId: 'email', signal: 'Rule creator, destination, scope, and creation time', evidenceStatus: 'partial', gapType: 'detection' },
    collection: { action: 'Sensitive threads and attachments are gathered', detail: 'Messages are searched and labelled before transfer.', technique: 'T1114 Email Collection', sourceId: 'email', signal: 'Search, access, attachment, and message identifiers', evidenceStatus: 'partial', gapType: 'telemetry' },
    exfiltration: { action: 'Mail is forwarded outside the organisation', detail: 'Messages and attachments are delivered through the forwarding rule.', technique: 'T1567 Exfiltration Over Web Service', sourceId: 'dlp', signal: 'Policy match, destination, attachment, and disposition', evidenceStatus: 'partial', gapType: 'detection', severity: 'critical' },
    concealment: { action: 'Forwarding rule is hidden among normal rules', detail: 'The rule uses a vague name and narrow conditions.', technique: 'T1114.003 Email Collection: Email Forwarding Rule', sourceId: 'email', signal: 'Rule inventory, changes, and last-used time', evidenceStatus: 'present' },
    response: { action: 'Rule, sessions, and delegated grants are revoked', detail: 'Containment removes every persistence path and scopes historical delivery.', sourceId: 'email', signal: 'Rule deletion, session revocation, and message trace', evidenceStatus: 'partial', gapType: 'response', controlEffect: 'contain' },
  },
});

export const threatModel: ThreatModel = {
  version: 'threat-model-0.3.0',
  note: 'Synthetic attack scenarios for assessing evidence, controls, gaps, and remediation. The 2D map and 3D view use the same data.',
  safety:
    'Demo data only. Do not enter private logs, tenant identifiers, hostnames, credentials, or unsafe samples into this public tool.',
  stages: attackChainStages,
  scenarios: [
    internalPreResignationExfiltration,
    internalPrivilegedSabotage,
    cyberPhishingToRansomware,
    cyberSaasTokenTheft,
    thirdPartyCloudExport,
    breakGlassCredentialMisuse,
    negligentExternalSharing,
    removableMediaTheft,
    businessRecordFraud,
    insiderCollusion,
    personalEmailForwarding,
    detectionPipelineSuppression,
  ],
};

export const gapTypeLabels: Record<GapType, string> = {
  telemetry: 'Telemetry gap',
  detection: 'Detection gap',
  response: 'Response gap',
  'accepted-risk': 'Accepted-risk gap',
};

export const gapTypeMeanings: Record<GapType, string> = {
  telemetry: 'Required events or fields are missing, unreliable, too short-lived, or not searchable. The stage is a blind zone.',
  detection: 'Telemetry exists but no tested analytic, alert, dashboard, or investigation path does. The attack passes without a credible alert.',
  response: 'Activity is visible but escalation, containment, evidence export, or ownership is unclear. An alert without timely containment.',
  'accepted-risk': 'The blind spot is consciously tolerated. It stays visible, stays neutral, and never renders as covered.',
};

export const controlEffectLabels: Record<ControlEffect, string> = {
  block: 'Blocks',
  detect: 'Detects',
  delay: 'Delays',
  contain: 'Contains',
  investigate: 'Supports investigation',
};

export const controlEffectMeanings: Record<ControlEffect, string> = {
  block: 'Prevents the action from succeeding.',
  detect: 'Raises a credible signal. It does not stop the action.',
  delay: 'Adds friction and buys response time. It does not stop the action.',
  contain: 'Limits the blast radius once the action is known.',
  investigate: 'Preserves evidence so the action can be reconstructed and explained.',
};

export function scenarioById(id: string): ThreatScenario | undefined {
  return threatModel.scenarios.find((scenario) => scenario.id === id);
}
