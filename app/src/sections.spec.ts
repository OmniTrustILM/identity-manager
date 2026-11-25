import { describe, expect, it } from 'vitest';
import { OverviewIcon } from './design-system/icons';
import { type Section, sections, visibleSections } from './sections';
import { inventory } from '../playwright/ilm';
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
        const open = sections.filter(({ visibleWhen }) => !visibleWhen);
        expect(visibleSections([], 'macos', null, sections)).toEqual(open);
    });

    it('shows a section when its rule accepts the listings', () => {
        expect(visibleSections(['things'], 'macos', null, candidates).map(({ id }) => id)).toEqual(['overview', 'certificates', 'gated']);
    });

    it('hides a section when its rule rejects the listings', () => {
        expect(visibleSections(['other'], 'macos', null, candidates).map(({ id }) => id)).toEqual(['overview', 'certificates']);
    });

    it('defaults to the real sections, with no inventory', () => {
        expect(visibleSections([], 'macos')).toEqual(sections.filter(({ visibleWhen }) => !visibleWhen));
    });
});

describe('requests section', () => {
    const prepared = inventory({
        prepared: [{ uuid: 'p', name: 'VPN', raProfile: { uuid: 'r', name: 'Corp' }, registration: null, subject: [] }],
    });
    const requests = inventory({ requests: [{ uuid: null, label: 'Mail', since: 1, state: 'beingIssued' }] });
    const ids = (view: Parameters<typeof visibleSections>[2], platform: 'macos' | 'windows' | 'linux' = 'macos') =>
        visibleSections([], platform, view).map(({ id }) => id);

    it('is hidden without the inventory and when the inventory has nothing for it', () => {
        expect(ids(null)).toEqual(['overview', 'certificates']);
        expect(ids(inventory())).toEqual(['overview', 'certificates']);
    });

    it.each([
        ['prepared certificates', prepared],
        ['own requests', requests],
    ])('follows Certificates when the inventory has %s', (_, view) => {
        expect(ids(view)).toEqual(['overview', 'certificates', 'requests']);
        expect(ids(view, 'windows')).toEqual(['overview', 'certificates', 'requests']);
        expect(visibleSections([], 'macos', view)[2]?.label).toBe(strings.requests);
    });

    it('is hidden on Linux', () => {
        expect(ids(prepared, 'linux')).toEqual(['overview']);
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
