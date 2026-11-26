import { mkdirSync } from 'node:fs';
import { expect, test } from '@playwright/experimental-ct-react';
import type { Locator, Page } from '@playwright/test';
import { keyboardReady } from '../../playwright/focus';
import { SettingsStory } from '../../playwright/stories';
import type { Platform, SessionView, SettingsView } from '../bridge';

type Scheme = 'light' | 'dark';

const view: SettingsView = {
    startAtLogin: { value: true, locked: false },
    logLevel: { value: 'debug', locked: true },
    ilmUrl: { value: null, locked: false },
    requireUnlock: { value: true, locked: false },
    lockAfterIdle: { value: null, locked: false },
    checkEvery: { value: 15, locked: false },
    warnDays: { value: 30, locked: false },
    automaticRenewal: { value: 'newKey', locked: false },
    unlock: 'unsupported',
};
const unlocked: SettingsView = {
    ...view,
    logLevel: { value: 'info', locked: false },
};

const shots = process.env.SIGN_IN_SHOTS;

const words: Record<Platform, string | null> = {
    macos: null,
    windows: 'Settings',
    linux: 'Preferences',
};
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
    story: { view: SettingsView; refuse?: string; session?: SessionView } = {
        view,
    },
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

/** On macOS each group is a pane of the Settings window, opened by its tab; elsewhere every group is on the page. */
async function openPane(page: Page, os: Platform, name: string) {
    if (os === 'macos') {
        await page.getByRole('tab', { name }).click();
    }
}

for (const scheme of ['light', 'dark'] as const) {
    test(`on macos in ${scheme} the toolbar names each pane and the keyboard moves between them`, async ({ mount, page }) => {
        await open(page, mount, 'macos', scheme, { view: ready });
        await keyboardReady(page);
        const tabs = page.getByRole('tab');
        await expect(tabs).toHaveText(['General', 'Security', 'Connection']);
        await expect(page.getByRole('tablist')).toHaveAttribute('data-tauri-drag-region', 'deep');

        await page.getByRole('tab', { name: 'General' }).focus();
        await page.keyboard.press('ArrowRight');
        await expect(page.getByRole('tab', { name: 'Security' })).toBeFocused();
        await expect(page.getByRole('tabpanel')).toHaveAccessibleName('Security');
        await expect(page.getByRole('switch', { name: securityLabels.macos })).toBeVisible();
        await expect(page.getByRole('switch', { name: 'Start at login' })).toHaveCount(0);
        await page.keyboard.press('End');
        await expect(page.getByRole('textbox', { name: 'ILM address' })).toBeVisible();
        if (shots) {
            mkdirSync(shots, { recursive: true });
            await page.screenshot({ path: `${shots}/settings-tabs-macos-${scheme}.png` });
        }
    });
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
            if (os === 'macos') {
                await expect(page.getByRole('tab', { name: 'General' })).toHaveAttribute('aria-selected', 'true');
            } else {
                await expect(page.getByRole('heading', { name: 'General' })).toBeVisible();
            }
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
    await open(page, mount, 'macos', 'light', {
        view: unlocked,
        refuse: 'LogLevel is managed by your organization',
    });

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
            await openPane(page, os, 'Connection');

            await expect(page.getByRole('heading', { name: 'Connection' })).toBeAttached();
            const address = page.getByRole('textbox', { name: 'ILM address' });
            await expect(address).toHaveValue('ilm.example.com');
            await expect(address).toHaveJSProperty('readOnly', os === 'macos');
            await expect(page.getByText('Alex Morgan')).toBeVisible();
            await expect(page.getByText('alex.morgan')).toBeVisible();
            await expect(page.getByRole('button', { name: 'Sign out' })).toBeVisible();
            if (shots) {
                mkdirSync(shots, { recursive: true });
                await page.screenshot({
                    path: `${shots}/settings-${os}-${scheme}.png`,
                });
            }
        });
    }
}

const certificateSession: SessionView = {
    state: 'signedIn',
    address: 'ilm.example.com',
    person: { name: 'Alex Morgan', username: 'alex.morgan' },
    allowedListings: [],
    certificate: '3F:A2:9C:01',
    unreachable: false,
};

for (const os of ['macos', 'windows'] as const) {
    for (const scheme of ['light', 'dark'] as const) {
        test(`on ${os} in ${scheme} the account row of a certificate session shows the short fingerprint`, async ({ mount, page }) => {
            await open(page, mount, os, scheme, {
                view: unlocked,
                session: certificateSession,
            });
            await page.setViewportSize(connection(os));
            await openPane(page, os, 'Connection');

            await expect(page.getByText('Signed in with a certificate')).toBeVisible();
            await expect(page.getByText('3F:A2:9C:01')).toBeVisible();
            await expect(page.getByText('alex.morgan')).toHaveCount(0);
            await expect(page.getByRole('button', { name: 'Sign out' })).toBeVisible();
            if (shots) {
                mkdirSync(shots, { recursive: true });
                await page.screenshot({
                    path: `${shots}/settings-certificate-${os}-${scheme}.png`,
                });
            }
        });
    }
}

test('an address set by the organization is locked and says so', async ({ mount, page }) => {
    await open(page, mount, 'windows', 'light', {
        view: {
            ...unlocked,
            ilmUrl: { value: 'ilm.example.com', locked: true },
            requireUnlock: { value: true, locked: false },
            lockAfterIdle: { value: null, locked: false },
        },
    });

    const address = page.getByRole('textbox', { name: 'ILM address' });
    await expect(address).toBeDisabled();
    await expect(address).toHaveAccessibleDescription('Managed by your organization');
});

test('the keyboard alone changes the address, and a refused address shows its reason', async ({ mount, page }) => {
    await open(page, mount, 'linux', 'light', {
        view: unlocked,
        refuse: 'The address must start with https://',
    });
    await keyboardReady(page);
    await page.getByRole('combobox', { name: 'Warn before expiry' }).focus();

    await page.keyboard.press('Tab');
    await expect(page.getByRole('textbox', { name: 'ILM address' })).toBeFocused();
    await page.keyboard.press('ControlOrMeta+a');
    await page.keyboard.type('http://ilm.example.org');
    await page.keyboard.press('Enter');

    await expect(page.getByRole('alert')).toHaveText('The address must start with https://');
    await page.keyboard.press('Tab');
    await expect(page.getByRole('button', { name: 'Sign out' })).toBeFocused();
});

const ready: SettingsView = { ...unlocked, unlock: 'available' };
const securityLabels = { macos: 'Ask for Touch ID or your password to unlock', windows: 'Ask for Windows Hello to unlock' } as const;

for (const os of ['macos', 'windows'] as const) {
    for (const scheme of ['light', 'dark'] as const) {
        test(`on ${os} in ${scheme} the group Security has its switch and its select by name`, async ({ mount, page }) => {
            await open(page, mount, os, scheme, { view: ready });
            await page.setViewportSize(connection(os));
            await openPane(page, os, 'Security');

            await expect(page.getByRole('heading', { name: 'Security' })).toBeAttached();
            await expect(page.getByRole('switch', { name: securityLabels[os] })).toBeChecked();
            const idle = page.getByRole('combobox', { name: 'Lock after inactivity' });
            await expect(idle).toBeEnabled();
            await expect(idle).toHaveValue('never');
            await expect(idle.locator('option')).toHaveText(['Never', '5 minutes', '15 minutes', '30 minutes', '60 minutes']);
        });
    }
}

test('on Linux there is no group Security', async ({ mount, page }) => {
    await open(page, mount, 'linux', 'light', { view: unlocked });

    await expect(page.getByRole('heading', { name: 'Security' })).toHaveCount(0);
});

test('the keyboard alone turns unlocking off, which disables the time and skips it', async ({ mount, page }) => {
    await open(page, mount, 'macos', 'light', { view: ready });
    await openPane(page, 'macos', 'Security');
    await keyboardReady(page);
    const unlockSwitch = page.getByRole('switch', { name: securityLabels.macos });
    await unlockSwitch.focus();

    await page.keyboard.press('Space');
    await expect(unlockSwitch).not.toBeChecked();
    const idle = page.getByRole('combobox', { name: 'Lock after inactivity' });
    await expect(idle).toBeDisabled();
    await page.keyboard.press('Tab');
    await expect(idle).not.toBeFocused();
});

test('the keyboard alone reaches the time and chooses it', async ({ mount, page }) => {
    await open(page, mount, 'windows', 'light', { view: ready });
    await keyboardReady(page);
    await page.getByRole('switch', { name: securityLabels.windows }).focus();

    await page.keyboard.press('Tab');
    const idle = page.getByRole('combobox', { name: 'Lock after inactivity' });
    await expect(idle).toBeFocused();
    await idle.selectOption('15');
    await expect(idle).toHaveValue('15');
});

test('a time set by the organization is locked, shown in minutes and says so', async ({ mount, page }) => {
    await open(page, mount, 'macos', 'dark', { view: { ...ready, lockAfterIdle: { value: 7, locked: true } } });
    await openPane(page, 'macos', 'Security');

    const idle = page.getByRole('combobox', { name: 'Lock after inactivity' });
    await expect(idle).toBeDisabled();
    await expect(idle).toHaveValue('7');
    await expect(idle).toHaveAccessibleDescription('Managed by your organization');
});

for (const scheme of ['light', 'dark'] as const) {
    test(`on windows in ${scheme} Windows Hello not set up disables both rows and says how to set it up`, async ({ mount, page }) => {
        await open(page, mount, 'windows', scheme, { view: { ...ready, unlock: 'notSetUp' } });

        const unlockSwitch = page.getByRole('switch', { name: securityLabels.windows });
        await expect(unlockSwitch).toBeDisabled();
        await expect(unlockSwitch).not.toBeChecked();
        await expect(unlockSwitch).toHaveAccessibleDescription('Set up Windows Hello to lock Identity Manager.');
        await expect(page.getByRole('combobox', { name: 'Lock after inactivity' })).toBeDisabled();
    });
}

test('on macOS without a password both rows are disabled and say how to set one', async ({ mount, page }) => {
    await open(page, mount, 'macos', 'light', { view: { ...ready, unlock: 'notSetUp' } });
    await openPane(page, 'macos', 'Security');

    await expect(page.getByRole('switch', { name: securityLabels.macos })).toHaveAccessibleDescription(
        'Set a password for this Mac to lock Identity Manager.',
    );
    await expect(page.getByRole('combobox', { name: 'Lock after inactivity' })).toBeDisabled();
});

for (const scheme of ['light', 'dark'] as const) {
    test(`in ${scheme} Check ILM every offers four times by name and sends the chosen one`, async ({ mount, page }) => {
        await open(page, mount, 'macos', scheme, { view: unlocked });

        const every = page.getByRole('combobox', { name: 'Check ILM every' });
        await expect(every).toBeEnabled();
        await expect(every).toHaveValue('15');
        await expect(every.locator('option')).toHaveText(['5 minutes', '15 minutes', '30 minutes', '60 minutes']);
        await every.selectOption('60');
        await expect(every).toHaveValue('60');
    });

    test(`in ${scheme} a check time set by the organization is locked and one outside the list shows its minutes`, async ({
        mount,
        page,
    }) => {
        await open(page, mount, 'windows', scheme, { view: { ...unlocked, checkEvery: { value: 120, locked: true } } });

        const every = page.getByRole('combobox', { name: 'Check ILM every' });
        await expect(every).toBeDisabled();
        await expect(every).toHaveValue('120');
        await expect(every.locator('option:checked')).toHaveText('120 minutes');
        await expect(every).toHaveAccessibleDescription('Managed by your organization');
    });
}

for (const scheme of ['light', 'dark'] as const) {
    test(`in ${scheme} Warn before expiry offers five times by name and sends the chosen one`, async ({ mount, page }) => {
        await open(page, mount, 'macos', scheme, { view: unlocked });

        const warn = page.getByRole('combobox', { name: 'Warn before expiry' });
        await expect(warn).toBeEnabled();
        await expect(warn).toHaveValue('30');
        await expect(warn.locator('option')).toHaveText(['7 days', '14 days', '30 days', '60 days', '90 days']);
        await warn.selectOption('60');
        await expect(warn).toHaveValue('60');
    });

    test(`in ${scheme} a warning time set by the organization is locked and one outside the list shows its days`, async ({
        mount,
        page,
    }) => {
        await open(page, mount, 'windows', scheme, { view: { ...unlocked, warnDays: { value: 45, locked: true } } });

        const warn = page.getByRole('combobox', { name: 'Warn before expiry' });
        await expect(warn).toBeDisabled();
        await expect(warn).toHaveValue('45');
        await expect(warn.locator('option:checked')).toHaveText('45 days');
        await expect(warn).toHaveAccessibleDescription('Managed by your organization');
    });
}

test('the keyboard alone reaches Warn before expiry after Check ILM every and chooses a time', async ({ mount, page }) => {
    await open(page, mount, 'windows', 'light', { view: unlocked });
    await keyboardReady(page);

    await page.getByRole('combobox', { name: 'Check ILM every' }).focus();
    await page.keyboard.press('Tab');
    await expect(page.getByRole('combobox', { name: 'Warn before expiry' })).toBeFocused();
    await page.getByRole('combobox', { name: 'Warn before expiry' }).selectOption('60');
    await expect(page.getByRole('combobox', { name: 'Warn before expiry' })).toHaveValue('60');
});
