import { mkdirSync } from 'node:fs';
import { expect, test } from '@playwright/experimental-ct-react';
import type { Locator, Page } from '@playwright/test';
import { keyboardReady } from '../../playwright/focus';
import { SignInStory } from '../../playwright/stories';
import type { Platform, ProviderChoice, SessionView } from '../bridge';

type Scheme = 'light' | 'dark';
type Idle = Extract<SessionView, { state: 'signedOut' }>;

const shots = process.env.SIGN_IN_SHOTS;
const idle: Idle = { state: 'signedOut', address: 'ilm.example.com', locked: false, problem: null };
const managed: Idle = { ...idle, locked: true };
const failed: Idle = { ...idle, problem: 'This ILM does not publish how to sign in' };
const providers: ProviderChoice[] = [
    { id: '0', name: 'Company SSO' },
    { id: '1', name: 'Microsoft Entra ID' },
    { id: '2', name: 'Okta' },
];

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
const buttons: Record<Platform, Record<Scheme, string>> = {
    macos: { light: 'rgb(242, 242, 242)', dark: 'rgb(47, 47, 47)' },
    windows: { light: 'rgb(241, 241, 241)', dark: 'rgb(51, 51, 51)' },
    linux: { light: 'rgb(220, 220, 220)', dark: 'rgb(61, 61, 64)' },
};
const metrics: Record<Platform, { form: number; field: number; button: number; title: string }> = {
    macos: { form: 340, field: 28, button: 32, title: '22px' },
    windows: { form: 380, field: 32, button: 36, title: '28px' },
    linux: { form: 380, field: 34, button: 38, title: '24px' },
};
const sizes: Record<Platform, { width: number; height: number }> = {
    macos: { width: 521, height: 381 },
    windows: { width: 761, height: 409 },
    linux: { width: 761, height: 395 },
};

type Story = { view: Idle; providers?: ProviderChoice[]; refuse?: string };

async function open(
    page: Page,
    mount: (component: React.ReactElement) => Promise<Locator>,
    os: Platform,
    scheme: Scheme,
    story: Story = { view: idle },
) {
    await page.emulateMedia({ colorScheme: scheme, reducedMotion: 'reduce' });
    await page.setViewportSize(sizes[os]);
    await page.evaluate((system) => {
        document.documentElement.dataset.os = system;
    }, os);
    await mount(<SignInStory platform={os} {...story} />);
    await expect(page.getByRole('heading', { level: 1 })).toBeVisible();
}

async function shoot(page: Page, name: string) {
    if (shots) {
        mkdirSync(shots, { recursive: true });
        await page.screenshot({ path: `${shots}/${name}.png` });
    }
}

const style = (locator: Locator, property: string) =>
    locator.evaluate((element, name) => getComputedStyle(element).getPropertyValue(name), property);
const box = async (locator: Locator) => (await locator.boundingBox()) ?? { width: 0, height: 0 };

for (const os of ['macos', 'windows', 'linux'] as const) {
    for (const scheme of ['light', 'dark'] as const) {
        const want = metrics[os];
        const common = async (page: Page) => {
            await expect(page.getByRole('main')).toHaveCSS('background-color', surfaces[os][scheme]);
            expect(await style(page.getByRole('heading', { level: 1 }), 'font-size')).toBe(want.title);
        };

        test(`on ${os} in ${scheme} Connect is as designed`, async ({ mount, page }) => {
            await open(page, mount, os, scheme);

            await expect(page.getByRole('heading', { level: 1, name: 'Connect to your ILM' })).toBeVisible();
            const field = page.getByRole('textbox', { name: 'ILM address' });
            const next = page.getByRole('button', { name: 'Continue' });
            await expect(field).toHaveValue('ilm.example.com');
            expect((await box(field)).height).toBe(want.field);
            expect((await box(field)).width).toBe(want.form);
            expect((await box(next)).height).toBe(want.button);
            await expect(next).toHaveCSS('background-color', accents[os][scheme]);
            await common(page);
            await shoot(page, `connect-${os}-${scheme}`);
        });

        test(`on ${os} in ${scheme} Welcome is as designed`, async ({ mount, page }) => {
            await open(page, mount, os, scheme, { view: managed });

            await expect(page.getByRole('heading', { level: 1, name: 'Welcome' })).toBeVisible();
            const field = page.getByRole('textbox', { name: 'ILM address' });
            await expect(field).toHaveJSProperty('readOnly', true);
            await expect(field).toHaveAccessibleDescription('Managed by your organization');
            await expect(field).toHaveCSS('background-color', buttons[os][scheme]);
            await expect(page.getByRole('button', { name: 'Sign in' })).toBeVisible();
            await common(page);
            await shoot(page, `welcome-${os}-${scheme}`);
        });

        test(`on ${os} in ${scheme} Choose provider is as designed`, async ({ mount, page }) => {
            await open(page, mount, os, scheme, { view: idle, providers });
            await page.getByRole('button', { name: 'Continue' }).click();

            await expect(page.getByRole('heading', { level: 1, name: 'Choose how to sign in' })).toBeVisible();
            const names = page.getByRole('button');
            await expect(names).toHaveText(['Company SSO', 'Microsoft Entra ID', 'Okta']);
            await expect(names.first()).toHaveCSS('background-color', buttons[os][scheme]);
            expect((await box(names.first())).height).toBe(want.button);
            await common(page);
            await shoot(page, `choose-${os}-${scheme}`);
        });

        test(`on ${os} in ${scheme} Waiting is as designed`, async ({ mount, page }) => {
            await open(page, mount, os, scheme, { view: idle, providers });
            await page.getByRole('button', { name: 'Continue' }).click();
            await page.getByRole('button', { name: 'Company SSO' }).click();

            await expect(page.getByRole('heading', { level: 1, name: 'Continue in your browser' })).toBeVisible();
            await expect(page.getByRole('status')).toHaveText('Finish signing in with Company SSO, then return to this window.');
            await expect(page.getByRole('button', { name: 'Open the browser again' })).toHaveCSS('background-color', buttons[os][scheme]);
            await expect(page.getByRole('button', { name: 'Cancel' })).toHaveCSS('color', accents[os][scheme]);
            await common(page);
            await shoot(page, `waiting-${os}-${scheme}`);
        });

        test(`on ${os} in ${scheme} the Connect error is as designed`, async ({ mount, page }) => {
            await open(page, mount, os, scheme, { view: failed });

            const field = page.getByRole('textbox', { name: 'ILM address' });
            await expect(page.getByRole('alert')).toHaveText('This ILM does not publish how to sign in');
            await expect(field).toHaveAttribute('aria-invalid', 'true');
            await expect(field).toHaveAccessibleDescription('This ILM does not publish how to sign in');
            if (os !== 'linux') {
                await expect(field).toHaveCSS(
                    'border-top-color',
                    os === 'macos'
                        ? scheme === 'light'
                            ? 'rgb(255, 59, 48)'
                            : 'rgb(255, 69, 58)'
                        : scheme === 'light'
                          ? 'rgb(196, 43, 28)'
                          : 'rgb(255, 153, 164)',
                );
            }
            await common(page);
            await shoot(page, `error-${os}-${scheme}`);
        });
    }
}

test('the keyboard alone goes through Connect, Choose provider and Waiting', async ({ mount, page }) => {
    await open(page, mount, 'linux', 'light', { view: { ...idle, address: null }, providers });
    await keyboardReady(page);
    const field = page.getByRole('textbox', { name: 'ILM address' });
    await expect(field).toBeFocused();

    await page.keyboard.type('ilm.example.com');
    await page.keyboard.press('Enter');

    await expect(page.getByRole('heading', { level: 1, name: 'Choose how to sign in' })).toBeVisible();
    await expect(page.getByRole('button', { name: 'Company SSO' })).toBeFocused();
    await page.keyboard.press('Tab');
    await expect(page.getByRole('button', { name: 'Microsoft Entra ID' })).toBeFocused();
    await page.keyboard.press('Enter');

    await expect(page.getByRole('heading', { level: 1, name: 'Continue in your browser' })).toBeVisible();
    await expect(page.getByRole('button', { name: 'Open the browser again' })).toBeFocused();
    await expect(page.getByRole('status')).toHaveText('Finish signing in with Microsoft Entra ID, then return to this window.');
    await page.keyboard.press('Tab');
    await expect(page.getByRole('button', { name: 'Cancel' })).toBeFocused();
    await page.keyboard.press('Space');

    await expect(page.getByRole('heading', { level: 1, name: 'Choose how to sign in' })).toBeVisible();
});

test('Continue stays unavailable until there is an address, and the field is named for a screen reader', async ({ mount, page }) => {
    await open(page, mount, 'windows', 'light', { view: { ...idle, address: null } });

    await expect(page.getByRole('button', { name: 'Continue' })).toBeDisabled();
    await page.getByRole('textbox', { name: 'ILM address' }).fill('ilm.example.com');
    await expect(page.getByRole('button', { name: 'Continue' })).toBeEnabled();
});

test('a refused address is shown under the field and the person can try again', async ({ mount, page }) => {
    await open(page, mount, 'macos', 'light', { view: idle, refuse: 'The address must start with https://' });

    await page.getByRole('button', { name: 'Continue' }).click();

    await expect(page.getByRole('alert')).toHaveText('The address must start with https://');
    await page.getByRole('textbox', { name: 'ILM address' }).fill('ilm.example.org');
    await expect(page.getByRole('alert')).toHaveCount(0);
});
