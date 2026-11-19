import { expect, test } from '@playwright/experimental-ct-react';
import { TraySummaryStory } from '../../../playwright/stories';
import type { Locator, Page } from '@playwright/test';
import { keyboardReady } from '../../../playwright/focus';
import type { Platform, SessionView } from '../../bridge';

type Scheme = 'light' | 'dark';

const controls: Record<Platform, string> = { macos: '28px', windows: '32px', linux: '34px' };
const surfaces: Record<Platform, Record<Scheme, string>> = {
    macos: { light: 'rgba(0, 0, 0, 0)', dark: 'rgba(0, 0, 0, 0)' },
    windows: { light: 'rgb(251, 251, 251)', dark: 'rgb(39, 39, 39)' },
    linux: { light: 'rgb(250, 250, 251)', dark: 'rgb(34, 34, 38)' },
};

type Story = { session?: SessionView; seen?: (command: string) => void };

async function open(
    page: Page,
    mount: (component: React.ReactElement) => Promise<Locator>,
    os: Platform,
    scheme: Scheme,
    story: Story = {},
) {
    await page.emulateMedia({ colorScheme: scheme });
    await page.evaluate((system) => {
        document.documentElement.dataset.os = system;
    }, os);
    return mount(<TraySummaryStory platform={os} {...story} />);
}

for (const os of ['macos', 'windows', 'linux'] as const) {
    for (const scheme of ['light', 'dark'] as const) {
        test(`on ${os} in ${scheme} the summary has the tray width, its surface and the control height`, async ({ mount, page }) => {
            const summary = await open(page, mount, os, scheme);

            const measured = await summary.evaluate((element) => {
                const style = getComputedStyle(element);
                const control = document.querySelector('button');
                const probe = document.createElement('span');
                probe.style.fontFamily = 'var(--im-font-family)';
                document.body.append(probe);
                const tokenFont = getComputedStyle(probe).fontFamily;
                probe.remove();
                return {
                    width: element.getBoundingClientRect().width,
                    background: style.backgroundColor,
                    usesTokenFont: style.fontFamily === tokenFont,
                    height: control ? getComputedStyle(control).height : null,
                };
            });

            expect(measured).toEqual({ width: 340, background: surfaces[os][scheme], usesTokenFont: true, height: controls[os] });
        });
    }
}

test('the summary fills the window height, so nothing shows below it', async ({ mount, page }) => {
    await page.setViewportSize({ width: 340, height: 300 });
    const summary = await open(page, mount, 'windows', 'light');

    const [outer, header, button] = await Promise.all([
        summary.boundingBox(),
        page.getByRole('heading').boundingBox(),
        page.getByRole('button').boundingBox(),
    ]);

    expect(outer?.height).toBeGreaterThan((header?.height ?? 0) + (button?.height ?? 0));
    expect(outer?.height).toBe(300);
});

test('the open button is reachable by role and name and has focus when the summary shows', async ({ mount, page }) => {
    await open(page, mount, 'linux', 'light');

    await expect(page.getByRole('button', { name: 'Open Identity Manager' })).toBeFocused();
    await expect(page.getByRole('heading', { name: 'Identity Manager' })).toBeVisible();
    await expect(page.getByText('Version 0.1.0')).toBeVisible();
});

test('the focused button shows a focus ring', async ({ mount, page }) => {
    await open(page, mount, 'windows', 'light');

    const button = page.getByRole('button', { name: 'Open Identity Manager' });
    await expect(button).toBeFocused();

    await expect(button).not.toHaveCSS('outline-style', 'none');
});

const signedOut: SessionView = { state: 'signedOut', address: null, locked: false, problem: 'Your sign-in has ended.', again: true };
const lines: [string, SessionView, string][] = [
    [
        'signed in',
        {
            state: 'signedIn',
            address: 'https://develop-02.example.com',
            person: { name: 'Alex Morgan', username: 'alex.morgan' },
            allowedListings: [],
            certificate: null,
            unreachable: false,
        },
        'Signed in to develop-02.example.com as Alex Morgan',
    ],
    [
        'unreachable',
        { state: 'unreachable', address: 'https://develop-02.example.com', problem: 'timed out' },
        'Cannot reach develop-02.example.com',
    ],
    ['signed out', signedOut, 'Signed out'],
    ['locked', { state: 'locked' }, 'Identity Manager is locked'],
];

for (const [name, session, line] of lines) {
    test(`the summary says "${line}" when ${name}`, async ({ mount, page }) => {
        await open(page, mount, 'macos', 'light', { session });

        await expect(page.getByText(line)).toBeVisible();
    });
}

for (const os of ['macos', 'windows', 'linux'] as const) {
    test(`on ${os} the action sits above Open, which turns secondary, and has the focus`, async ({ mount, page }) => {
        await open(page, mount, os, 'light', { session: { state: 'locked' } });

        const unlock = page.getByRole('button', { name: 'Unlock' });
        const openApp = page.getByRole('button', { name: 'Open Identity Manager' });
        await expect(unlock).toBeFocused();
        const [above, below] = await Promise.all([unlock.boundingBox(), openApp.boundingBox()]);
        expect(above?.y).toBeLessThan(below?.y ?? 0);
        const background = (locator: Locator) => locator.evaluate((element) => getComputedStyle(element).backgroundColor);
        expect(await background(unlock)).not.toBe(await background(openApp));
    });
}

test('the keyboard alone reaches Sign in again and Open in that order and presses Sign in again', async ({ mount, page }) => {
    const seen: string[] = [];
    await open(page, mount, 'windows', 'light', { session: signedOut, seen: (command) => seen.push(command) });
    await keyboardReady(page);

    await expect(page.getByRole('button', { name: 'Sign in again' })).toBeFocused();
    await page.keyboard.press('Tab');
    await expect(page.getByRole('button', { name: 'Open Identity Manager' })).toBeFocused();
    await page.keyboard.press('Shift+Tab');
    await page.keyboard.press('Enter');

    await expect.poll(() => seen).toContain('sign_in_again');
});

test('the keyboard alone presses Unlock', async ({ mount, page }) => {
    const seen: string[] = [];
    await open(page, mount, 'linux', 'dark', { session: { state: 'locked' }, seen: (command) => seen.push(command) });
    await keyboardReady(page);

    await expect(page.getByRole('button', { name: 'Unlock' })).toBeFocused();
    await page.keyboard.press('Space');

    await expect.poll(() => seen).toContain('unlock');
});
