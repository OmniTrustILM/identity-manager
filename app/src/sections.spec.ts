import { describe, expect, it } from 'vitest';
import { OverviewIcon } from './design-system/icons';
import { type Section, sections, visibleSections } from './sections';

const gated: Section = {
    id: 'gated',
    label: 'Gated',
    icon: OverviewIcon,
    Component: () => null,
    visibleWhen: (listings) => listings.includes('things'),
};
const candidates = [...sections, gated];

describe('visibleSections', () => {
    it('keeps the sections without a rule whatever the listings', () => {
        expect(visibleSections([], sections)).toEqual(sections);
    });

    it('shows a section when its rule accepts the listings', () => {
        expect(visibleSections(['things'], candidates).map(({ id }) => id)).toEqual(['overview', 'gated']);
    });

    it('hides a section when its rule rejects the listings', () => {
        expect(visibleSections(['other'], candidates).map(({ id }) => id)).toEqual(['overview']);
    });

    it('defaults to the real sections', () => {
        expect(visibleSections([])).toEqual(sections);
    });
});
