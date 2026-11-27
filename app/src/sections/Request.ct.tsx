import { expect, test } from '@playwright/experimental-ct-react';
import type { Locator, Page } from '@playwright/test';
import { attributeField, attributeForm } from '../../playwright/attributes';
import { keyboardReady } from '../../playwright/focus';
import { type Requesting, RequestStory } from '../../playwright/stories';
import type { Platform, RaProfileChoice } from '../bridge';

type Scheme = 'light' | 'dark';

const profile = (name: string, authority: string): RaProfileChoice => ({
    uuid: `ra-${name}`,
    name,
    description: `${name} for people.`,
    authority,
    authority_uuid: 'ca-1',
});
const profiles = [profile('User mTLS', 'Example Issuing CA 2'), profile('Code signing', 'Example Code Signing CA')];
const forms = {
    request: attributeForm(
        [
            attributeField('cn', { label: 'Common name', value: { kind: 'text', value: 'Alex Morgan' } }),
            attributeField('o', { label: 'Organization', readOnly: true, value: { kind: 'text', value: 'Example Corp' } }),
        ],
        { id: 'form-request' },
    ),
    issue: attributeForm([attributeField('validity', { label: 'Validity' })], { id: 'form-issue' }),
    custom: attributeForm([attributeField('owner', { label: 'Owner' })], { id: 'form-custom' }),
};
const requesting: Requesting = {
    profiles,
    forms,
    offers: {
        storages: [{ storage: 'keychain', keyTypes: ['rsa2048', 'ecP256', 'ecP384'], defaultKeyType: 'ecP256' }],
        defaultStorage: 'keychain',
    },
    follow: [{ state: 'installed', storage: 'keychain', validUntil: new Date(2027, 10, 10).getTime() }],
};
const surfaces: Record<Platform, Record<Scheme, string>> = {
    macos: { light: 'rgb(255, 255, 255)', dark: 'rgb(30, 30, 30)' },
    windows: { light: 'rgb(251, 251, 251)', dark: 'rgb(39, 39, 39)' },
    linux: { light: 'rgb(255, 255, 255)', dark: 'rgb(30, 30, 30)' },
};

async function open(
    page: Page,
    mount: (component: React.ReactElement) => Promise<Locator>,
    os: Platform,
    scheme: Scheme,
    over: Partial<Requesting> = {},
) {
    await page.emulateMedia({ colorScheme: scheme, reducedMotion: 'reduce' });
    await page.setViewportSize({ width: 760, height: 760 });
    await page.evaluate((system) => {
        document.documentElement.dataset.os = system;
    }, os);
    await mount(<RequestStory platform={os} requesting={{ ...requesting, ...over }} />);
    await page.getByRole('dialog').waitFor();
}

const dialog = (page: Page) => page.getByRole('dialog', { name: 'Request a certificate' });

for (const os of ['macos', 'windows'] as const) {
    for (const scheme of ['light', 'dark'] as const) {
        test(`on ${os} in ${scheme} the sheet has its surface and walks the steps to the installed certificate`, async ({
            mount,
            page,
        }) => {
            await open(page, mount, os, scheme);
            const sheet = dialog(page);
            expect(await sheet.evaluate((element) => getComputedStyle(element).backgroundColor)).toBe(surfaces[os][scheme]);
            await expect(sheet.getByRole('list', { name: 'Steps' }).getByRole('listitem')).toHaveCount(4);
            await expect(sheet.locator('[aria-current="step"]')).toHaveText('1Profile');
            await expect(sheet.getByRole('radiogroup', { name: 'RA profiles' }).getByRole('radio')).toHaveCount(2);
            await expect(sheet.getByText('Authority: Example Issuing CA 2')).toBeVisible();

            await sheet.getByRole('button', { name: 'Continue' }).click();
            await expect(sheet.locator('[aria-current="step"]')).toHaveText('2Attributes');
            await expect(sheet.getByRole('heading', { level: 3 })).toHaveText([
                'Fill in the attributes',
                'Certificate request',
                'From the RA profile',
                'Custom attributes',
            ]);
            await expect(sheet.getByRole('button', { name: 'Continue' })).toBeEnabled();
            await sheet.getByRole('button', { name: 'Continue' }).click();

            await expect(sheet.getByText('Where should the private key live?')).toBeVisible();
            await expect(sheet.getByText(`The key is created on this ${os === 'macos' ? 'Mac' : 'PC'} and never leaves it.`)).toBeVisible();
            await expect(sheet.getByRole('radio', { name: /Keychain/ })).toBeChecked();
            await expect(sheet.getByText('Recommended')).toBeVisible();
            await expect(sheet.getByRole('combobox', { name: 'Key type' })).toHaveValue('ecP256');
            await sheet.getByRole('button', { name: 'Continue' }).click();

            await expect(sheet.getByText('Review and request')).toBeVisible();
            await expect(sheet.getByText('Alex Morgan, Example Corp')).toBeVisible();
            await sheet.getByRole('button', { name: 'Request certificate' }).click();

            await expect(sheet.getByText('Your certificate is installed')).toBeVisible();
            await expect(sheet.getByText('Keychain', { exact: true })).toBeVisible();
            await sheet.getByRole('button', { name: 'Done' }).click();
            await expect(page.getByRole('dialog')).toHaveCount(0);
        });
    }
}

test('the order of the buttons follows the system', async ({ mount, page }) => {
    await open(page, mount, 'macos', 'light');
    await expect(dialog(page).getByRole('button')).toHaveText(['Cancel', 'Continue']);
});

test('on Windows the confirming button comes first', async ({ mount, page }) => {
    await open(page, mount, 'windows', 'light');
    await expect(dialog(page).getByRole('button')).toHaveText(['Continue', 'Cancel']);
});

test('with one profile the sheet opens on the attributes', async ({ mount, page }) => {
    await open(page, mount, 'macos', 'light', { profiles: [profiles[0] as RaProfileChoice] });
    await expect(dialog(page).locator('[aria-current="step"]')).toHaveText('2Attributes');
});

test('the keyboard alone chooses the profile and the storage and requests', async ({ mount, page }) => {
    await open(page, mount, 'windows', 'light', {
        forms: { request: null, issue: null, custom: null },
        offers: {
            storages: [
                { storage: 'software', keyTypes: ['rsa2048'], defaultKeyType: 'rsa2048' },
                { storage: 'tpm', keyTypes: ['ecP256', 'rsa2048'], defaultKeyType: 'ecP256' },
            ],
            defaultStorage: 'tpm',
        },
    });
    await keyboardReady(page);
    const sheet = dialog(page);

    await sheet.getByRole('radio', { name: /User mTLS/ }).focus();
    await page.keyboard.press('ArrowDown');
    await expect(sheet.getByRole('radio', { name: /Code signing/ })).toBeChecked();
    await sheet.getByRole('button', { name: 'Continue' }).focus();
    await page.keyboard.press('Enter');
    await expect(sheet.getByRole('heading', { name: 'Fill in the attributes' })).toBeFocused();
    await sheet.getByRole('button', { name: 'Continue' }).focus();
    await page.keyboard.press('Enter');

    await expect(sheet.getByRole('radio', { name: /TPM/ })).toBeChecked();
    await expect(sheet.getByText('Windows key store')).toBeVisible();
    await sheet.getByRole('radio', { name: /Windows key store/ }).check();
    await expect(sheet.getByRole('combobox', { name: 'Key type' }).locator('option')).toHaveText(['RSA 2048']);
    await sheet.getByRole('button', { name: 'Continue' }).click();
    await expect(sheet.getByText('New, in the Windows key store')).toBeVisible();
    await expect(sheet.getByText('Your personal certificate store')).toBeVisible();
});

test('a policy that allows no storage leaves Continue off', async ({ mount, page }) => {
    await open(page, mount, 'macos', 'dark', {
        profiles: [profiles[0] as RaProfileChoice],
        forms: { request: null, issue: null, custom: null },
        offers: { storages: [], defaultStorage: null },
    });
    await dialog(page).getByRole('button', { name: 'Continue' }).click();

    await expect(dialog(page).getByText('Your organization does not allow a key storage on this computer.')).toBeVisible();
    await expect(dialog(page).getByRole('button', { name: 'Continue' })).toBeDisabled();
});

test('a request that waits says so and can be closed', async ({ mount, page }) => {
    await open(page, mount, 'macos', 'light', {
        profiles: [profiles[0] as RaProfileChoice],
        forms: { request: null, issue: null, custom: null },
        follow: [{ state: 'waiting', stage: 'pendingApproval' }],
    });
    const sheet = dialog(page);
    await sheet.getByRole('button', { name: 'Continue' }).click();
    await sheet.getByRole('button', { name: 'Continue' }).click();
    await sheet.getByRole('button', { name: 'Request certificate' }).click();

    await expect(sheet.getByText('Waiting for approval')).toBeVisible();
    await expect(sheet.getByText('The app installs it when ILM issues it. You can close this window.')).toBeVisible();
    await expect(sheet.getByRole('button')).toHaveText(['Done']);
});

test('a refused request is back on the attributes with an alert that names ILM’s messages', async ({ mount, page }) => {
    await open(page, mount, 'windows', 'light', {
        profiles: [profiles[0] as RaProfileChoice],
        refuse: { kind: 'refused', messages: ["Common name is required by RA profile 'User mTLS'."] },
    });
    const sheet = dialog(page);
    await sheet.getByRole('button', { name: 'Continue' }).click();
    await sheet.getByRole('button', { name: 'Continue' }).click();
    await sheet.getByRole('button', { name: 'Request certificate' }).click();

    await expect(sheet.getByRole('alert')).toContainText('ILM did not accept the request');
    await expect(sheet.getByRole('alert')).toContainText("Common name is required by RA profile 'User mTLS'.");
    await expect(sheet.locator('[aria-current="step"]')).toHaveText('2Attributes');
});
