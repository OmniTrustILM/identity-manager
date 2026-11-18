import { mkdirSync } from 'node:fs';
import { expect, test } from '@playwright/experimental-ct-react';
import type { Locator, Page } from '@playwright/test';
import { keyboardReady } from '../../playwright/focus';
import { SettingsStory } from '../../playwright/stories';
import type { Platform, SettingsView } from '../bridge';

type Scheme = 'light' | 'dark';

const view: SettingsView = {
    startAtLogin: { value: true, locked: false },
    logLevel: { value: 'debug', locked: true },
    ilmUrl: { value: null, locked: false },
};
const unlocked: SettingsView = { ...view, logLevel: { value: 'info', locked: false } };

const shots = process.env.SIGN_IN_SHOTS;

const words: Record<Platform, string | null> = { macos: null, windows: 'Settings', linux: 'Preferences' };
const cards: Record<Platform, Record<Scheme, string>> = {
    macos: { light: 'rgb(255, 255, 255)', dark: 'rgb(30, 30, 30)' },
    windows: { light: 'rgb(241, 241, 241)', dark: 'rgb(52, 52, 52)' },
    linux: { light: 'rgb(235, 235, 237)', dark: 'rgb(46, 46, 50)' },
};

async function open(
    page: Page,
    mount: (component: React.ReactElement) => Promise<Locator>,
    os: Platform,
    scheme: Scheme,
    story: { view: SettingsView; refuse?: string } = { view },
) {
    await page.emulateMedia({ colorScheme: scheme, reducedMotion: 'reduce' });
    await page.setViewportSize(os === 'macos' ? { width: 520, height: 300 } : { width: 760, height: 420 });
    await page.evaluate((system) => {
        document.documentElement.dataset.os = system;
    }, os);
    await mount(<SettingsStory platform={os} {...story} />);
    const word = words[os];
    if (word) {
        await page.getByRole('button', { name: word }).click();
    }
    await expect(page.getByRole('switch', { name: 'Start at login' })).toBeVisible();
}

for (const os of ['macos', 'windows', 'linux'] as const) {
    for (const scheme of ['light', 'dark'] as const) {
        test(`on ${os} in ${scheme} the rows, the lock note and the heading are as designed`, async ({ mount, page }) => {
            await open(page, mount, os, scheme);

            await expect(page.getByRole('switch', { name: 'Start at login' })).toBeChecked();
            const level = page.getByRole('combobox', { name: 'Log level' });
            await expect(level).toBeDisabled();
            await expect(level).toHaveValue('debug');
            await expect(level).toHaveAccessibleDescription('Managed by your organization');
            await expect(page.getByText('Managed by your organization')).toBeVisible();
            await expect(page.getByRole('heading', { name: 'General' })).toBeVisible();
            const heading = page.getByRole('heading', { level: 1 });
            const word = words[os];
            if (word) {
                await expect(heading).toHaveText(word);
            } else {
                await expect(heading).toHaveCount(0);
            }
            const card = await page
                .getByRole('switch', { name: 'Start at login' })
                .evaluate(
                    (element, system) =>
                        getComputedStyle(
                            (system === 'windows'
                                ? element.closest('div[class*="border-separator"]')
                                : element.closest('section > div')) as Element,
                        ).backgroundColor,
                    os,
                );
            expect(card).toBe(cards[os][scheme]);
        });
    }
}

test('the keyboard alone changes the switch and the page shows the stored value', async ({ mount, page }) => {
    await open(page, mount, 'linux', 'light', { view: unlocked });
    await keyboardReady(page);
    await page.getByRole('button', { name: 'Overview' }).focus();
    await page.getByRole('button', { name: 'Preferences' }).focus();

    await page.keyboard.press('Tab');
    await expect(page.getByRole('switch', { name: 'Start at login' })).toBeFocused();
    await page.keyboard.press('Space');
    await expect(page.getByRole('switch', { name: 'Start at login' })).not.toBeChecked();
    await page.keyboard.press('Tab');
    await expect(page.getByRole('combobox', { name: 'Log level' })).toBeFocused();
    await page.getByRole('combobox', { name: 'Log level' }).selectOption('warn');
    await expect(page.getByRole('combobox', { name: 'Log level' })).toHaveValue('warn');
});

test('on Windows the state word follows the switch', async ({ mount, page }) => {
    await open(page, mount, 'windows', 'light', { view: unlocked });

    await expect(page.getByText('On', { exact: true })).toBeVisible();
    await page.getByRole('switch', { name: 'Start at login' }).click();

    await expect(page.getByText('Off', { exact: true })).toBeVisible();
});

test('a refused change shows its reason under the row and keeps the stored value', async ({ mount, page }) => {
    await open(page, mount, 'macos', 'light', { view: unlocked, refuse: 'LogLevel is managed by your organization' });

    await page.getByRole('combobox', { name: 'Log level' }).selectOption('warn');

    await expect(page.getByRole('alert')).toHaveText('LogLevel is managed by your organization');
    await expect(page.getByRole('combobox', { name: 'Log level' })).toHaveValue('info');
    await expect(page.getByRole('combobox', { name: 'Log level' })).toHaveAccessibleDescription('LogLevel is managed by your organization');
});

const connection = (os: Platform) => (os === 'macos' ? { width: 520, height: 420 } : { width: 760, height: 640 });

for (const os of ['macos', 'windows', 'linux'] as const) {
    for (const scheme of ['light', 'dark'] as const) {
        test(`on ${os} in ${scheme} the group Connection shows the address, the person and Sign out`, async ({ mount, page }) => {
            await open(page, mount, os, scheme, { view: unlocked });
            await page.setViewportSize(connection(os));

            await expect(page.getByRole('heading', { name: 'Connection' })).toBeVisible();
            const address = page.getByRole('textbox', { name: 'ILM address' });
            await expect(address).toHaveValue('ilm.example.com');
            await expect(address).toHaveJSProperty('readOnly', os === 'macos');
            await expect(page.getByText('Alex Morgan')).toBeVisible();
            await expect(page.getByText('alex.morgan')).toBeVisible();
            await expect(page.getByRole('button', { name: 'Sign out' })).toBeVisible();
            if (shots) {
                mkdirSync(shots, { recursive: true });
                await page.screenshot({ path: `${shots}/settings-${os}-${scheme}.png` });
            }
        });
    }
}

test('an address set by the organization is locked and says so', async ({ mount, page }) => {
    await open(page, mount, 'windows', 'light', { view: { ...unlocked, ilmUrl: { value: 'ilm.example.com', locked: true } } });

    const address = page.getByRole('textbox', { name: 'ILM address' });
    await expect(address).toBeDisabled();
    await expect(address).toHaveAccessibleDescription('Managed by your organization');
});

test('the keyboard alone changes the address, and a refused address shows its reason', async ({ mount, page }) => {
    await open(page, mount, 'linux', 'light', { view: unlocked, refuse: 'The address must start with https://' });
    await keyboardReady(page);
    await page.getByRole('combobox', { name: 'Log level' }).focus();

    await page.keyboard.press('Tab');
    await expect(page.getByRole('textbox', { name: 'ILM address' })).toBeFocused();
    await page.keyboard.press('ControlOrMeta+a');
    await page.keyboard.type('http://ilm.example.org');
    await page.keyboard.press('Enter');

    await expect(page.getByRole('alert')).toHaveText('The address must start with https://');
    await page.keyboard.press('Tab');
    await expect(page.getByRole('button', { name: 'Sign out' })).toBeFocused();
});
