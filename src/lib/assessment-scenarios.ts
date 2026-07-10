/**
 * Compatibility re-export.
 *
 * Assessment readiness scenarios are derived from the threat-model library via
 * build-assessment-scenarios and exposed on catalogue.threatScenarios.
 */
export {
  buildAssessmentScenario,
  buildAssessmentScenarios,
  scenarioVectorMap,
  assessmentSourceOverrides,
} from './build-assessment-scenarios';

import { catalogue } from '../data/catalogue';
import { threatModel } from '../data/threat-model';
import { buildAssessmentScenarios } from './build-assessment-scenarios';

export const assessmentScenarios = catalogue.threatScenarios;

export function assessmentScenarioCoverageComplete(): boolean {
  const derived = buildAssessmentScenarios(threatModel.scenarios);
  if (derived.length !== threatModel.scenarios.length) return false;
  const derivedIds = new Set(derived.map((scenario) => scenario.id));
  return threatModel.scenarios.every((scenario) => derivedIds.has(scenario.id));
}
