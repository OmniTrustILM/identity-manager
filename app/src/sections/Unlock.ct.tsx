import { expect, test } from '@playwright/experimental-ct-react';
import type { Locator, Page } from '@playwright/test';
import { keyboardReady } from '../../playwright/focus';
import { UnlockStory } from '../../playwright/stories';
import type { Platform } from '../bridge';

type Scheme = 'light' | 'dark';

const surfaces: Record<Platform, Record<Scheme, string>> = {
    macos: { light: 'rgb(255, 255, 255)', dark: 'rgb(30, 30, 30)' },
    windows: { light: 'rgb(251, 251, 251)', dark: 'rgb(39, 39, 39)' },
    linux: { light: 'rgb(250, 250, 251)', dark: 'rgb(34, 34, 38)' },
};
const accents: Record<Platform, Record<Scheme, string>> = {
    macos: { light: 'rgb(0, 122, 255)', dark: 'rgb(10, 132, 255)' },
    windows: { light: 'rgb(0, 95, 184)', dark: 'rgb(96, 205, 255)' },
    linux: { light: 'rgb(53, 132, 228)', dark: 'rgb(53, 132, 228)' },
};
const buttons: Record<Platform, number> = { macos: 32, windows: 36, linux: 38 };

async function open(
    page: Page,
    mount: (component: React.ReactElement) => Promise<Locator>,
    os: Platform,
    scheme: Scheme,
    story: { refuse?: string; automatic?: boolean; seen?: (command: string) => void } = {},
) {
    await page.emulateMedia({ colorScheme: scheme, reducedMotion: 'reduce' });
    await page.evaluate((system) => {
        document.documentElement.dataset.os = system;
    }, os);
    return mount(<UnlockStory platform={os} {...story} />);
}

for (const os of ['macos', 'windows', 'linux'] as const) {
    for (const scheme of ['light', 'dark'] as const) {
        test(`on ${os} in ${scheme} Unlock has its surface, the accent button and the refusal under it`, async ({ mount, page }) => {
            await open(page, mount, os, scheme, { refuse: 'Unlock was cancelled.' });
            await page.getByRole('button', { name: 'Unlock' }).click();

            await expect(page.getByRole('alert')).toHaveText('Unlock was cancelled.');
            const measured = await page.evaluate(() => {
                const button = document.querySelector('button') as HTMLElement;
                const alert = document.querySelector('[role="alert"]') as HTMLElement;
                const main = document.querySelector('main') as HTMLElement;
                return {
                    surface: getComputedStyle(main).backgroundColor,
                    button: getComputedStyle(button).backgroundColor,
                    height: button.getBoundingClientRect().height,
                    below: alert.getBoundingClientRect().top >= button.getBoundingClientRect().bottom,
                };
            });
            expect(measured).toEqual({ surface: surfaces[os][scheme], button: accents[os][scheme], height: buttons[os], below: true });
        });
    }
}

test('Unlock is a heading and a button, and the button has the keyboard focus', async ({ mount, page }) => {
    await open(page, mount, 'linux', 'light');

    await expect(page.getByRole('heading', { name: 'Identity Manager is locked' })).toBeVisible();
    await expect(page.getByRole('button', { name: 'Unlock' })).toBeFocused();
});

test('the keyboard alone asks to unlock and a refusal is announced and can be retried', async ({ mount, page }) => {
    const seen: string[] = [];
    await open(page, mount, 'windows', 'light', { refuse: 'Unlock was cancelled.', seen: (command) => seen.push(command) });
    await keyboardReady(page);

    await page.keyboard.press('Enter');
    await expect(page.getByRole('alert')).toHaveText('Unlock was cancelled.');
    await page.keyboard.press('Space');

    await expect.poll(() => seen).toEqual(['unlock', 'unlock']);
});

test('the main window asks once as it opens', async ({ mount, page }) => {
    const seen: string[] = [];
    await open(page, mount, 'macos', 'dark', { refuse: 'Unlock was cancelled.', automatic: true, seen: (command) => seen.push(command) });

    await expect(page.getByRole('alert')).toHaveText('Unlock was cancelled.');
    expect(seen).toEqual(['unlock']);
});

test('the focused button shows a focus ring', async ({ mount, page }) => {
    await open(page, mount, 'windows', 'dark');

    await expect(page.getByRole('button', { name: 'Unlock' })).not.toHaveCSS('outline-style', 'none');
});
