import { describe, expect, it } from 'vitest';
import { glossary } from './glossary';
import { sourceMetadata } from './source-metadata';

function normalizeTerm(value: string) {
  return value.toLowerCase().replace(/[^a-z0-9]+/g, ' ').trim();
}

describe('glossary', () => {
  it('defines every term referenced by source metadata', () => {
    const defined = new Set(glossary.map((item) => normalizeTerm(item.term)));
    const referenced = Object.values(sourceMetadata).flatMap((item) => item.glossaryTerms);
    const missing = referenced.filter((term) => !defined.has(normalizeTerm(term)));

    expect(missing).toEqual([]);
  });

  it('uses unique terms and complete decision-oriented definitions', () => {
    const normalized = glossary.map((item) => normalizeTerm(item.term));
    expect(new Set(normalized).size).toBe(normalized.length);

    for (const item of glossary) {
      expect(item.category).toBeTruthy();
      expect(item.plainEnglish.length).toBeGreaterThan(20);
      expect(item.whyItMatters.length).toBeGreaterThan(20);
    }
  });

  it('keeps prevention, detection, containment, and evidence readiness distinct', () => {
    const byTerm = new Map(glossary.map((item) => [item.term, item]));
    expect(byTerm.get('Preventive control')?.whyItMatters).toMatch(/would stop/i);
    expect(byTerm.get('Detection')?.whyItMatters).toMatch(/would not stop/i);
    expect(byTerm.get('Containment')?.whyItMatters).toMatch(/would stop the path/i);
    expect(byTerm.get('Investigation-ready')?.whyItMatters).toMatch(/does not mean.*prevented/i);
  });
});
