import { expect, test } from '@playwright/experimental-ct-react';
import type { Locator, Page } from '@playwright/test';
import { keyboardReady } from '../../playwright/focus';
import { attentionCertificates, attentionInventory, attentionItems, inventory, summary } from '../../playwright/ilm';
import { OverviewStory } from '../../playwright/stories';
import type { Platform } from '../bridge';

type Scheme = 'light' | 'dark';
type System = 'macos' | 'windows';

const attention: Record<System, Record<Scheme, string>> = {
    macos: { light: 'rgb(201, 52, 0)', dark: 'rgb(255, 159, 10)' },
    windows: { light: 'rgb(157, 93, 0)', dark: 'rgb(252, 225, 0)' },
};
const bad: Record<System, Record<Scheme, string>> = {
    macos: { light: 'rgb(200, 16, 28)', dark: 'rgb(255, 130, 121)' },
    windows: { light: 'rgb(189, 38, 25)', dark: 'rgb(255, 153, 164)' },
};
const surfaces: Record<System, Record<Scheme, string>> = {
    macos: { light: 'rgb(255, 255, 255)', dark: 'rgb(30, 30, 30)' },
    windows: { light: 'rgb(251, 251, 251)', dark: 'rgb(39, 39, 39)' },
};

const items = [
    attentionItems.revoked,
    attentionItems.expired,
    attentionItems.expiring,
    attentionItems.later,
    { kind: 'notInIlm' as const, count: 3 },
];
const normal = { summary: summary(items), certificates: attentionCertificates, inventory: attentionInventory() };

async function open(
    page: Page,
    mount: (component: React.ReactElement) => Promise<Locator>,
    os: Platform,
    scheme: Scheme,
    story: Partial<React.ComponentProps<typeof OverviewStory>> = {},
) {
    await page.emulateMedia({ colorScheme: scheme, reducedMotion: 'reduce' });
    await page.setViewportSize({ width: 1100, height: 860 });
    await page.evaluate((system) => {
        document.documentElement.dataset.os = system;
    }, os);
    await mount(<OverviewStory platform={os} {...normal} {...story} />);
    await page.getByRole('heading', { name: 'Overview', level: 1 }).waitFor();
}

for (const os of ['macos', 'windows'] as const) {
    for (const scheme of ['light', 'dark'] as const) {
        test(`on ${os} in ${scheme} the items, the zero tile and the bars use the colours of the tokens`, async ({ mount, page }) => {
            await open(page, mount, os, scheme, {
                summary: summary(items, { counts: { valid: 3, expiring: 0, expired: 2, notInIlm: 3 } }),
            });
            await expect(page.getByText('Expires on', { exact: false }).first()).toBeVisible();

            const measured = await page.evaluate(() => {
                const colour = (element: Element | null | undefined) => (element ? getComputedStyle(element).color : null);
                const background = (element: Element | null | undefined) => (element ? getComputedStyle(element).backgroundColor : null);
                const byText = (selector: string, start: string) =>
                    [...document.querySelectorAll(selector)].find((candidate) => candidate.textContent?.startsWith(start));
                const tiles = [...document.querySelectorAll('ul[aria-label] > li')];
                const bars = [...document.querySelectorAll('ol[aria-label] > li [aria-hidden]')] as HTMLElement[];
                return {
                    surface: background(document.querySelector('main')?.parentElement),
                    expiring: colour(byText('section span', 'Expires on')),
                    revoked: colour(byText('section span', 'Revoked')),
                    full: colour(tiles[0]?.firstElementChild),
                    zero: colour(tiles[1]?.firstElementChild),
                    bar: background(bars[1]),
                    stub: background(bars[0]),
                    barHeight: bars[1]?.getBoundingClientRect().height,
                    stubHeight: bars[0]?.getBoundingClientRect().height,
                };
            });

            expect(measured.surface).toBe(surfaces[os][scheme]);
            expect(measured.expiring).toBe(attention[os][scheme]);
            expect(measured.revoked).toBe(bad[os][scheme]);
            expect(measured.zero).not.toBe(measured.full);
            expect(measured.bar).not.toBe(measured.stub);
            expect(measured.barHeight).toBeGreaterThan(measured.stubHeight ?? 0);
            expect(measured.stubHeight).toBe(2);
        });
    }
}

test('Overview is the first and the current entry of the sidebar', async ({ mount, page }) => {
    await open(page, mount, 'macos', 'light');

    const nav = page.getByRole('navigation');
    await expect(nav.getByRole('button')).toHaveText(['Overview', 'Certificates', 'Settings…']);
    await expect(nav.getByRole('button', { name: 'Overview' })).toHaveAttribute('aria-current', 'page');
    await expect(page.getByText(/^Checked with ILM at /)).toBeVisible();
    await expect(page.getByRole('button', { name: 'Sync now' })).toBeEnabled();
});

test('the counts are a list named by what it counts, one item per state', async ({ mount, page }) => {
    await open(page, mount, 'windows', 'light');

    const counts = page.getByRole('list', { name: 'Certificates by state' });
    await expect(counts.getByRole('listitem')).toHaveText(['3Valid', '2Expiring soon', '2Expired', '3Not in ILM']);
});

test('the chart is a list of twelve months with their counts as text, the current month first', async ({ mount, page }) => {
    await open(page, mount, 'macos', 'dark');

    const months = page.getByRole('list', { name: 'Certificates expiring in each of the next 12 months' }).getByRole('listitem');
    await expect(months).toHaveCount(12);
    const now = new Date();
    const names = Array.from({ length: 12 }, (_, index) =>
        new Intl.DateTimeFormat('en-US', { month: 'short' }).format(new Date(now.getFullYear(), now.getMonth() + index, 1)),
    );
    await expect(months).toHaveText([0, 2, 0, 1, 0, 1, 0, 1, 0, 2, 0, 1].map((count, index) => `${count}${names[index]}`));
    await expect(page.getByRole('list', { name: 'Certificates expiring soon' }).getByRole('listitem')).toHaveText([
        /^vpn\.example\.com expires on .*, in 13 days$/,
        /^Alex Novak expires on .*, in 29 days$/,
    ]);
});

test('Show opens Certificates with that certificate selected', async ({ mount, page }) => {
    await open(page, mount, 'windows', 'light');

    await page.getByRole('button', { name: 'Show vpn.example.com' }).click();

    await expect(page.getByRole('heading', { name: 'Certificates', level: 1 })).toBeVisible();
    await expect(page.getByRole('option', { name: /^vpn\.example\.com/ })).toHaveAttribute('aria-selected', 'true');
    await expect(page.getByRole('heading', { name: 'vpn.example.com', level: 2 })).toBeVisible();
});

test('the keyboard alone reaches Show and opens the certificate', async ({ mount, page }) => {
    await open(page, mount, 'macos', 'light');
    await keyboardReady(page);

    await page.getByRole('button', { name: 'Sync now' }).focus();
    await page.keyboard.press('Tab');
    await expect(page.getByRole('button', { name: 'Show Build server' })).toBeFocused();
    await page.keyboard.press('Tab');
    await page.keyboard.press('Tab');
    await expect(page.getByRole('button', { name: 'Show vpn.example.com' })).toBeFocused();
    await page.keyboard.press('Enter');

    await expect(page.getByRole('option', { name: /^vpn\.example\.com/ })).toHaveAttribute('aria-selected', 'true');
});

test('Add to ILM opens the dialog with the three certificates ILM does not know, all checked', async ({ mount, page }) => {
    await open(page, mount, 'macos', 'light');

    await expect(page.getByText('3 certificates on this Mac are not in ILM')).toBeVisible();
    await expect(page.getByText('wifi-corp, vpn-client and Lab device')).toBeVisible();
    await page.getByRole('button', { name: 'Add to ILM' }).click();

    const dialog = page.getByRole('dialog', { name: 'Add 3 certificates to ILM' });
    await expect(dialog).toBeVisible();
    await expect(dialog.getByRole('checkbox')).toHaveCount(3);
    for (const box of await dialog.getByRole('checkbox').all()) {
        await expect(box).toBeChecked();
    }
    await expect(dialog.getByRole('button', { name: 'Add 3 to ILM' })).toBeFocused();
});

test('offline the item is still said but cannot be added, and the check says ILM cannot be reached', async ({ mount, page }) => {
    await open(page, mount, 'windows', 'dark', {
        inventory: attentionInventory({ status: { state: 'offline', since: Date.now() - 60000, reason: 'no route', unreachable: true } }),
    });

    await expect(page.getByText('3 certificates on this PC are not in ILM')).toBeVisible();
    await expect(page.getByRole('button', { name: 'Add to ILM' })).toHaveCount(0);
    await expect(page.getByText(/^Cannot reach ILM\. Shown as of /)).toBeVisible();
    await expect(page.getByRole('button', { name: /^Show / })).toHaveCount(4);
});

test('with nothing to attend to it says so', async ({ mount, page }) => {
    await open(page, mount, 'macos', 'light', {
        summary: summary([], { counts: { valid: 7, expiring: 0, expired: 1, notInIlm: 0 }, months: [0, 0, 1, 0, 0, 1, 0, 0, 2, 1, 0, 1] }),
    });

    await expect(page.getByText('Nothing needs attention.')).toBeVisible();
    await expect(page.getByRole('heading', { name: 'Needs attention' })).toBeVisible();
    await expect(page.getByRole('list', { name: 'Certificates expiring soon' })).toHaveCount(0);
    await expect(page.getByRole('list', { name: 'Certificates by state' }).getByRole('listitem')).toHaveText([
        '7Valid',
        '0Expiring soon',
        '1Expired',
        '0Not in ILM',
    ]);
});

for (const os of ['macos', 'windows'] as const) {
    test(`with no certificates on the ${os === 'macos' ? 'Mac' : 'PC'} it says so and draws no chart`, async ({ mount, page }) => {
        await open(page, mount, os, 'light', {
            summary: summary([], { counts: { valid: 0, expiring: 0, expired: 0, notInIlm: 0 }, months: Array(12).fill(0) as never }),
            certificates: [],
            inventory: inventory(),
        });

        await expect(page.getByText(`No certificates with a private key on this ${os === 'macos' ? 'Mac' : 'PC'}.`)).toBeVisible();
        await expect(page.getByRole('heading', { name: 'Expiry over the next 12 months' })).toHaveCount(0);
        await expect(page.getByRole('heading', { name: 'Needs attention' })).toHaveCount(0);
    });
}

test('without the listing there is no Not in ILM tile and nothing to add', async ({ mount, page }) => {
    await open(page, mount, 'macos', 'dark', {
        summary: summary(items.slice(0, 4), { listed: false, counts: { valid: 3, expiring: 2, expired: 2, notInIlm: null } }),
        inventory: attentionInventory({ listed: false, checked: [], matches: {} }),
    });

    await expect(page.getByRole('list', { name: 'Certificates by state' }).getByRole('listitem')).toHaveText([
        '3Valid',
        '2Expiring soon',
        '2Expired',
    ]);
    await expect(page.getByRole('button', { name: 'Add to ILM' })).toHaveCount(0);
});
