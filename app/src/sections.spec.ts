import { describe, expect, it } from 'vitest';
import { OverviewIcon } from './design-system/icons';
import { type Section, sections, visibleSections } from './sections';
import { strings } from './strings';

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
        expect(visibleSections([], 'macos', sections)).toEqual(sections);
    });

    it('shows a section when its rule accepts the listings', () => {
        expect(visibleSections(['things'], 'macos', candidates).map(({ id }) => id)).toEqual(['overview', 'certificates', 'gated']);
    });

    it('hides a section when its rule rejects the listings', () => {
        expect(visibleSections(['other'], 'macos', candidates).map(({ id }) => id)).toEqual(['overview', 'certificates']);
    });

    it('defaults to the real sections', () => {
        expect(visibleSections([], 'macos')).toEqual(sections);
    });
});

describe('certificates section', () => {
    it.each(['macos', 'windows'] as const)('follows Overview on %s', (platform) => {
        const shown = visibleSections([], platform);

        expect(shown.map(({ id }) => id)).toEqual(['overview', 'certificates']);
        expect(shown[1]?.label).toBe(strings.certificates);
    });

    it('is hidden on Linux whatever the listings', () => {
        expect(visibleSections(['things'], 'linux').map(({ id }) => id)).toEqual(['overview']);
    });
});
