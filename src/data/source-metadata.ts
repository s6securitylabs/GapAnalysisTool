import type { LogSourceId } from './catalogue';

export type RemediationStatus = 'not-started' | 'planned' | 'in-progress' | 'blocked' | 'accepted-risk' | 'verified';
export type RemediationPriority = 'critical' | 'high' | 'medium' | 'low';

export interface SourceMetadata {
  glossaryTerms: string[];
  privacyNotes: string[];
  remediation: {
    gapOwner: string;
    businessOwner: string;
    recommendation: string;
    targetDate: string;
    status: RemediationStatus;
    priority: RemediationPriority;
    notes: string;
  };
}

export const sourceMetadata: Record<LogSourceId, SourceMetadata> = {
  'idp-auth': {
    glossaryTerms: ['conditional access', 'MFA', 'token revocation'],
    privacyNotes: ['Use identity telemetry to prove session lifecycle and access changes, not to infer employee intent.'],
    remediation: {
      gapOwner: 'Identity engineering',
      businessOwner: 'IAM program manager',
      recommendation: 'Validate sign-in, MFA, and session-end telemetry with searchable retention and actor/device correlation.',
      targetDate: '2026-08-01',
      status: 'planned',
      priority: 'critical',
      notes: 'Identity evidence is foundational to most scenarios.',
    },
  },
  'endpoint-edr': {
    glossaryTerms: ['process lineage', 'removable media', 'sensor tamper'],
    privacyNotes: ['Limit endpoint review to approved investigative scope and documented evidence handling.'],
    remediation: {
      gapOwner: 'Endpoint security',
      businessOwner: 'Workplace engineering',
      recommendation: 'Confirm process lineage, file copy, removable-media, and tamper events on managed endpoints.',
      targetDate: '2026-08-15',
      status: 'in-progress',
      priority: 'critical',
      notes: 'Needed for staging, concealment, and USB exfiltration evidence.',
    },
  },
  email: {
    glossaryTerms: ['mailbox audit', 'forwarding rule', 'delegate access'],
    privacyNotes: ['Email and collaboration data often carries sensitive or personal content; require documented purpose limitation.'],
    remediation: {
      gapOwner: 'Messaging security',
      businessOwner: 'Collaboration services owner',
      recommendation: 'Enable mailbox audit verification for forwarding, sent mail, attachments, and admin actions.',
      targetDate: '2026-08-22',
      status: 'planned',
      priority: 'high',
      notes: 'Use metadata and approved audit trails before requesting content access.',
    },
  },
  dlp: {
    glossaryTerms: ['DLP', 'policy disposition', 'channel coverage'],
    privacyNotes: ['DLP events show control outcomes, not complete data lineage; validate channel coverage before drawing conclusions.'],
    remediation: {
      gapOwner: 'Data protection engineering',
      businessOwner: 'Privacy and data governance',
      recommendation: 'Prove DLP inspection and disposition by channel so email, endpoint, SaaS, and web are not conflated.',
      targetDate: '2026-09-05',
      status: 'planned',
      priority: 'high',
      notes: 'Common false-confidence area when only one channel is enforced.',
    },
  },
  'file-access': {
    glossaryTerms: ['object-level audit', 'permission change', 'data classification'],
    privacyNotes: ['File and repo activity should be corroborated with business context before labeling access as malicious.'],
    remediation: {
      gapOwner: 'Platform telemetry',
      businessOwner: 'Engineering systems owner',
      recommendation: 'Prioritize read/export/delete and permission-change audit coverage on sensitive stores.',
      targetDate: '2026-08-29',
      status: 'planned',
      priority: 'critical',
      notes: 'High leverage for IP theft and unusual-valid-access cases.',
    },
  },
  vpn: {
    glossaryTerms: ['device posture', 'session lifecycle', 'assigned IP'],
    privacyNotes: ['Remote access logs are correlation context, not standalone proof of user behavior.'],
    remediation: {
      gapOwner: 'Network security',
      businessOwner: 'Remote access service owner',
      recommendation: 'Verify VPN login/logout and posture evidence where remote access is part of the operating model.',
      targetDate: '2026-09-12',
      status: 'not-started',
      priority: 'medium',
      notes: 'Useful context when other sources lack trusted device details.',
    },
  },
  'proxy-dns': {
    glossaryTerms: ['egress volume', 'DNS correlation', 'destination category'],
    privacyNotes: ['Web destinations and DNS should support corroboration, not become a browsing-surveillance feed.'],
    remediation: {
      gapOwner: 'Network security',
      businessOwner: 'Internet egress owner',
      recommendation: 'Improve user/device attribution and upload visibility for outbound web and storage paths.',
      targetDate: '2026-09-19',
      status: 'blocked',
      priority: 'high',
      notes: 'Blocked until shared egress identity mapping is fixed.',
    },
  },
  'saas-audit': {
    glossaryTerms: ['audit export', 'object action', 'external share'],
    privacyNotes: ['SaaS audit quality varies by license tier and product; validate fidelity before claiming readiness.'],
    remediation: {
      gapOwner: 'SaaS platform engineering',
      businessOwner: 'Business applications director',
      recommendation: 'Standardize evidence for download/export/share and admin actions across priority SaaS systems.',
      targetDate: '2026-08-12',
      status: 'in-progress',
      priority: 'critical',
      notes: 'One of the highest-leverage sources for business-system misuse.',
    },
  },
  'hr-case': {
    glossaryTerms: ['least privilege', 'purpose limitation', 'legal hold'],
    privacyNotes: ['HR and case data must stay minimum-necessary, approval-backed, and never used as standalone proof of risk.'],
    remediation: {
      gapOwner: 'HR systems',
      businessOwner: 'Internal scenario program manager',
      recommendation: 'Provide tightly governed lifecycle and approval context with audited investigator access.',
      targetDate: '2026-08-26',
      status: 'planned',
      priority: 'critical',
      notes: 'Sensitive workforce context requires governance and corroboration.',
    },
  },
  'physical-access': {
    glossaryTerms: ['badge event', 'restricted area', 'tailgate alarm'],
    privacyNotes: ['Physical access and location data require legal review and should corroborate cyber facts rather than imply motive.'],
    remediation: {
      gapOwner: 'Corporate security systems',
      businessOwner: 'Physical security manager',
      recommendation: 'Document when badge telemetry is appropriate, searchable, and approval-gated for investigations.',
      targetDate: '2026-09-02',
      status: 'planned',
      priority: 'medium',
      notes: 'Useful for restricted-area correlation, not generalized workforce monitoring.',
    },
  },
  'privileged-admin': {
    glossaryTerms: ['PAM', 'vault checkout', 'break glass'],
    privacyNotes: ['Privileged telemetry should be correlated to approved tickets and maintenance windows before escalation.'],
    remediation: {
      gapOwner: 'Privileged access engineering',
      businessOwner: 'Infrastructure operations director',
      recommendation: 'Prove session recording, command evidence, and ticket correlation for privileged activity.',
      targetDate: '2026-08-18',
      status: 'planned',
      priority: 'critical',
      notes: 'Critical for destructive action and privileged misuse scenarios.',
    },
  },
  'cloud-storage': {
    glossaryTerms: ['data events', 'ACL change', 'public link'],
    privacyNotes: ['Cloud object access should be prioritized by classification and ownership, not bulk-monitored without business context.'],
    remediation: {
      gapOwner: 'Cloud platform security',
      businessOwner: 'Cloud operations manager',
      recommendation: 'Enable sensitive object read/share/delete audit trails and map them to ownership and classification.',
      targetDate: '2026-08-30',
      status: 'planned',
      priority: 'high',
      notes: 'Volume and cost make selective enablement important.',
    },
  },
  'siem-enrichment': {
    glossaryTerms: ['normalization', 'correlation health', 'retention window'],
    privacyNotes: ['Correlation layers should improve investigative readiness, not hide broken raw-source quality beneath dashboards.'],
    remediation: {
      gapOwner: 'Detection engineering',
      businessOwner: 'SOC manager',
      recommendation: 'Validate freshness, parsing health, retention, searchable fields, and entity enrichment for each mapped source.',
      targetDate: '2026-08-08',
      status: 'in-progress',
      priority: 'critical',
      notes: 'This is the bridge between collection and investigation-ready use.',
    },
  },
};
