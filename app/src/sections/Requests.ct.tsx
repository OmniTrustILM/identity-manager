import { expect, test } from '@playwright/experimental-ct-react';
import type { Locator, Page } from '@playwright/test';
import { attributeField, attributeForm } from '../../playwright/attributes';
import { keyboardReady } from '../../playwright/focus';
import { inventory } from '../../playwright/ilm';
import { type Requesting, RequestsStory } from '../../playwright/stories';
import type { InventoryView, Platform, PreparedView } from '../bridge';

type Scheme = 'light' | 'dark';

const day = 24 * 60 * 60 * 1000;
const prepared = (name: string, registration: PreparedView['registration'], profile = 'Corporate VPN'): PreparedView => ({
    uuid: `uuid-${name}`,
    name,
    raProfile: { uuid: 'ra-1', name: profile },
    registration,
    subject: [
        { kind: 'commonName', value: 'vpn-alice', oid: null },
        { kind: 'organization', value: 'Example Corp', oid: null },
    ],
});
const full = () =>
    inventory({
        prepared: [
            prepared('VPN gateway access', { state: 'active', expiresAt: Date.now() + 5.5 * day }),
            prepared('Wi-Fi laptop', { state: 'expired', expiresAt: Date.now() - day }, 'Corporate Wi-Fi'),
            prepared('Remote desktop', { state: 'locked', expiresAt: null }),
        ],
        requests: [
            { uuid: 'r1', label: 'S/MIME email', since: Date.now() - day, state: 'pendingApproval' },
            { uuid: null, label: 'Developer signing', since: Date.now() - 3600_000, state: 'beingIssued' },
        ],
    });
const requesting: Requesting = {
    profiles: [],
    forms: {
        request: null,
        issue: attributeForm([attributeField('tag', { label: 'Device tag' })], { id: 'form-issue' }),
        custom: null,
    },
    offers: { storages: [{ storage: 'keychain', keyTypes: ['ecP256'] }], defaultStorage: 'keychain' },
    follow: [{ state: 'installed', storage: 'keychain', validUntil: new Date(2027, 10, 10).getTime() }],
};
const surfaces: Record<'macos' | 'windows', Record<Scheme, string>> = {
    macos: { light: 'rgb(255, 255, 255)', dark: 'rgb(30, 30, 30)' },
    windows: { light: 'rgb(251, 251, 251)', dark: 'rgb(39, 39, 39)' },
};

async function open(
    page: Page,
    mount: (component: React.ReactElement) => Promise<Locator>,
    os: Platform,
    scheme: Scheme,
    view: InventoryView = full(),
    over: Partial<Requesting> = {},
) {
    await page.emulateMedia({ colorScheme: scheme, reducedMotion: 'reduce' });
    await page.setViewportSize({ width: 1000, height: 800 });
    await page.evaluate((system) => {
        document.documentElement.dataset.os = system;
    }, os);
    await mount(<RequestsStory platform={os} inventory={view} requesting={{ ...requesting, ...over }} />);
    await page.getByRole('heading', { name: 'Requests', level: 1 }).waitFor();
}

for (const os of ['macos', 'windows'] as const) {
    for (const scheme of ['light', 'dark'] as const) {
        test(`on ${os} in ${scheme} the section lists what is ready and what is in progress`, async ({ mount, page }) => {
            await open(page, mount, os, scheme);

            await expect(page.getByText('1 ready to issue, 2 in progress')).toBeVisible();
            await expect(page.getByRole('heading', { level: 2 })).toHaveText(['Ready for you to issue', 'My requests']);
            await expect(page.getByText('Issue within 6 days')).toBeVisible();
            await expect(page.getByText('Issue window ended')).toBeVisible();
            await expect(page.getByText('Locked after too many attempts')).toBeVisible();
            await expect(page.getByText('Ask your administrator')).toHaveCount(2);
            await expect(page.getByText('Waiting for approval')).toBeVisible();
            await expect(page.getByText('Being issued')).toBeVisible();
            await expect(page.getByRole('button')).toHaveCount(1);
            const panel = page.getByRole('region', { name: 'Ready for you to issue' });
            expect(await panel.evaluate((element) => getComputedStyle(element.querySelector('ul') as Element).borderTopWidth)).toBe('1px');
            expect(await page.locator('main').evaluate((element) => getComputedStyle(element).backgroundColor)).toBe(surfaces[os][scheme]);
        });
    }
}

test('with nothing prepared and nothing waiting the page says so', async ({ mount, page }) => {
    await open(page, mount, 'macos', 'light', inventory());

    await expect(page.getByRole('heading', { name: 'Nothing to issue or follow' })).toBeVisible();
    await expect(page.getByText('Certificates your administrator prepares for you and the requests you send appear here.')).toBeVisible();
});

test('Issue… opens the sheet for the certificate and the steps reach the installed end', async ({ mount, page }) => {
    await open(page, mount, 'windows', 'light');
    await page.getByRole('button', { name: 'Issue VPN gateway access' }).click();

    const sheet = page.getByRole('dialog', { name: 'Issue VPN gateway access' });
    await expect(sheet.locator('[aria-current="step"]')).toHaveText('1Attributes');
    await expect(sheet.getByRole('heading', { name: 'Prepared by your administrator' })).toBeVisible();
    await expect(sheet.getByText('vpn-alice')).toBeVisible();
    await expect(sheet.getByLabel('Device tag')).toBeVisible();
    await sheet.getByRole('button', { name: 'Continue' }).click();
    await expect(sheet.getByText('Where should the private key live?')).toBeVisible();
    await sheet.getByRole('button', { name: 'Continue' }).click();

    await expect(sheet.getByLabel('Challenge')).toBeVisible();
    await expect(sheet.getByRole('button', { name: 'Issue certificate' })).toBeDisabled();
    await sheet.getByLabel('Challenge').fill('secret');
    await sheet.getByRole('button', { name: 'Issue certificate' }).click();
    await expect(sheet.getByText('Your certificate is installed')).toBeVisible();
});

test('a refused challenge is shown under the field, which is marked invalid and focused', async ({ mount, page }) => {
    await open(page, mount, 'macos', 'dark', full(), {
        refuse: { kind: 'refused', messages: ['The certificate registration challenge is invalid.'] },
    });
    await page.getByRole('button', { name: 'Issue VPN gateway access' }).click();
    const sheet = page.getByRole('dialog', { name: 'Issue VPN gateway access' });
    await sheet.getByRole('button', { name: 'Continue' }).click();
    await sheet.getByRole('button', { name: 'Continue' }).click();
    await sheet.getByLabel('Challenge').fill('wrong');
    await sheet.getByRole('button', { name: 'Issue certificate' }).click();

    const field = sheet.getByLabel('Challenge');
    await expect(field).toHaveAttribute('aria-invalid', 'true');
    await expect(field).toBeFocused();
    await expect(field).toHaveValue('');
    await expect(field).toHaveAccessibleDescription(/The certificate registration challenge is invalid\./);
    await expect(sheet.locator('[aria-current="step"]')).toHaveText('3Review');
});

test('the keyboard reaches Issue… and the sheet', async ({ mount, page }) => {
    await open(page, mount, 'windows', 'light');
    await keyboardReady(page);

    await page.getByRole('button', { name: 'Issue VPN gateway access' }).focus();
    await page.keyboard.press('Enter');

    const sheet = page.getByRole('dialog', { name: 'Issue VPN gateway access' });
    await expect(sheet.getByRole('heading', { name: 'Fill in the attributes' })).toBeFocused();
    await page.keyboard.press('Tab');
    await expect(sheet.getByLabel('Device tag')).toBeFocused();
});
