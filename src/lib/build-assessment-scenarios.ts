import type { LogSourceId, ThreatScenario as AssessmentScenario } from '../data/catalogue';
import type {
  AttackChainStageId,
  ThreatScenario as ModelScenario,
} from '../data/threat-model';

/**
 * Coarse catalogue flow stays stable for assessment UI; attack-chain stages map into it.
 * Response maps to impact so defender containment still appears on the readiness flowline.
 */
const attackStageToFlowStep: Record<AttackChainStageId, string> = {
  preparation: 'trigger',
  access: 'access',
  misuse: 'discovery',
  collection: 'collection',
  exfiltration: 'transfer',
  concealment: 'concealment',
  response: 'impact',
};

/** Canonical threat-model scenario id → assessment risk-vector ids. */
export const scenarioVectorMap: Record<string, string[]> = {
  'internal-pre-resignation-exfiltration': [
    'bulk-saas-download',
    'repo-clone-archive',
    'email-exfil-forwarding',
    'search-recon-sensitive-data',
    'external-share-cloud',
    'workforce-transition-control-failure',
  ],
  'internal-privileged-sabotage': [
    'privileged-outside-window',
    'destructive-admin',
    'concealment-log-tamper',
  ],
  'cyber-phishing-to-ransomware': [
    'ransomware-encryption-impact',
    'compromised-outsmarted-user',
    'destructive-admin',
    'concealment-log-tamper',
  ],
  'cyber-saas-token-theft': [
    'saas-token-abuse',
    'oauth-shadow-it',
    'email-exfil-forwarding',
  ],
  'business-email-compromise': [
    'business-email-compromise-payment',
    'email-exfil-forwarding',
    'compromised-outsmarted-user',
  ],
  'public-api-data-breach': [
    'api-object-level-authz-failure',
    'search-recon-sensitive-data',
  ],
  'software-supply-chain-compromise': [
    'software-dependency-compromise',
    'concealment-log-tamper',
  ],
  'public-cloud-storage-exposure': [
    'public-cloud-exposure',
    'external-share-cloud',
  ],
  'availability-extortion-ddos': [
    'availability-extortion',
  ],
  'third-party-cloud-export': [
    'access-retained-post-term',
    'bulk-saas-download',
    'unusual-valid-access',
    'workforce-transition-control-failure',
    'physical-cyber-anomaly',
  ],
  'break-glass-credential-misuse': [
    'privileged-outside-window',
    'mass-role-escalation',
    'destructive-admin',
  ],
  'detection-pipeline-suppression': [
    'detection-pipeline-suppression',
    'concealment-log-tamper',
  ],
  'negligent-external-sharing': [
    'negligent-mistaken-disclosure',
    'external-share-cloud',
  ],
  'removable-media-data-theft': [
    'removable-media-exfil',
  ],
  'business-record-fraud': [
    'business-record-tamper',
    'mass-role-escalation',
  ],
  'insider-collusion': [
    'collusion-cross-user',
    'physical-cyber-anomaly',
  ],
  'personal-email-forwarding': [
    'email-exfil-forwarding',
  ],
};

export interface AssessmentSourceOverride {
  criticalSources?: LogSourceId[];
  recommendedSources?: LogSourceId[];
}

/**
 * Optional per-scenario source overrides when frequency derivation is too thin
 * or assessment criticality should differ from raw stage evidence counts.
 */
export const assessmentSourceOverrides: Record<string, AssessmentSourceOverride> = {
  'internal-pre-resignation-exfiltration': {
    criticalSources: ['workforce-lifecycle', 'idp-auth', 'saas-audit', 'file-access'],
    recommendedSources: ['endpoint-edr', 'dlp', 'proxy-dns', 'siem-enrichment'],
  },
  'third-party-cloud-export': {
    criticalSources: ['workforce-lifecycle', 'identity-governance', 'idp-auth', 'saas-audit'],
    recommendedSources: ['cloud-storage', 'siem-enrichment', 'asset-custody'],
  },
  'removable-media-data-theft': {
    criticalSources: ['endpoint-edr', 'file-access'],
    recommendedSources: ['dlp', 'asset-custody', 'siem-enrichment', 'workforce-lifecycle'],
  },
  'insider-collusion': {
    criticalSources: ['idp-auth', 'saas-audit'],
    recommendedSources: ['file-access', 'workforce-lifecycle', 'case-management', 'siem-enrichment', 'cloud-storage'],
  },
  'break-glass-credential-misuse': {
    criticalSources: ['privileged-admin', 'idp-auth'],
    recommendedSources: ['cloud-storage', 'siem-enrichment', 'endpoint-edr'],
  },
};

const flowStepOrder = ['trigger', 'access', 'discovery', 'collection', 'transfer', 'impact', 'concealment'];

function deriveFlowStepIds(scenario: ModelScenario): string[] {
  const present = new Set<string>();
  for (const stage of scenario.stages) {
    if (stage.actorPresent === false) continue;
    present.add(attackStageToFlowStep[stage.stageId]);
  }
  return flowStepOrder.filter((id) => present.has(id));
}

function scoreSourceFrequency(scenario: ModelScenario): Map<LogSourceId, number> {
  const scores = new Map<LogSourceId, number>();
  for (const stage of scenario.stages) {
    if (stage.actorPresent === false) continue;
    const stageWeight =
      stage.stageId === 'access' || stage.stageId === 'collection' || stage.stageId === 'exfiltration'
        ? 2
        : 1;
    for (const evidence of stage.evidence) {
      const statusWeight = evidence.status === 'present' ? 3 : evidence.status === 'partial' ? 2 : 1;
      const highSeverityGap = stage.gaps.some((gap) => gap.severity === 'critical' || gap.severity === 'high');
      const severityBoost = highSeverityGap ? 1 : 0;
      const next = (scores.get(evidence.sourceId) ?? 0) + stageWeight * statusWeight + severityBoost;
      scores.set(evidence.sourceId, next);
    }
  }
  return scores;
}

function deriveSources(scenario: ModelScenario): {
  criticalSources: LogSourceId[];
  recommendedSources: LogSourceId[];
} {
  const override = assessmentSourceOverrides[scenario.id];
  if (override?.criticalSources && override.criticalSources.length > 0) {
    const critical = [...override.criticalSources];
    const criticalSet = new Set(critical);
    const recommended = (override.recommendedSources ?? []).filter((id) => !criticalSet.has(id));
    return { criticalSources: critical, recommendedSources: recommended };
  }

  const scores = scoreSourceFrequency(scenario);
  const ranked = [...scores.entries()].sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]));
  if (ranked.length === 0) {
    return { criticalSources: ['siem-enrichment'], recommendedSources: [] };
  }

  const criticalCount = Math.min(4, Math.max(2, Math.ceil(ranked.length * 0.45)));
  const criticalSources = ranked.slice(0, criticalCount).map(([id]) => id);
  const criticalSet = new Set(criticalSources);
  const recommendedSources = ranked.slice(criticalCount).map(([id]) => id).filter((id) => !criticalSet.has(id));
  return { criticalSources, recommendedSources };
}

function assessmentObjective(scenario: ModelScenario): string {
  // Keep actor objective from the threat model, framed for investigation readiness (not prevention claims).
  return `Investigate whether evidence can reconstruct: ${scenario.objective}`;
}

export function buildAssessmentScenario(scenario: ModelScenario): AssessmentScenario {
  const { criticalSources, recommendedSources } = deriveSources(scenario);
  const vectorIds = scenarioVectorMap[scenario.id] ?? [];
  return {
    id: scenario.id,
    title: scenario.title,
    objective: assessmentObjective(scenario),
    flowStepIds: deriveFlowStepIds(scenario),
    vectorIds,
    criticalSources,
    recommendedSources,
  };
}

export function buildAssessmentScenarios(scenarios: ModelScenario[]): AssessmentScenario[] {
  return scenarios.map(buildAssessmentScenario);
}
