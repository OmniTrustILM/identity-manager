import { expect, test } from '@playwright/experimental-ct-react';
import type { Locator, Page } from '@playwright/test';
import { keyboardReady } from '../../playwright/focus';
import { attentionCertificates } from '../../playwright/ilm';
import { AddToIlmStory } from '../../playwright/stories';
import type { AddChoicesView, AddResultView, Platform } from '../bridge';

type Scheme = 'light' | 'dark';
type System = 'macos' | 'windows';

const certificates = attentionCertificates.slice(4);
const choices: AddChoicesView = {
    groups: [
        { uuid: 'g-eng', name: 'Engineering' },
        { uuid: 'g-ops', name: 'Operations' },
    ],
    raProfiles: [{ uuid: 'ra-client', name: 'Client certificates', authority: 'Demo CA' }],
};
const results: AddResultView[] = [
    { fingerprint: 'LO:wifi-corp', outcome: 'added', messages: [] },
    { fingerprint: 'LO:vpn-client', outcome: 'addedNotManaged', messages: ['ILM does not allow this RA Profile.'] },
    { fingerprint: 'LO:Lab device', outcome: 'notAdded', messages: ['ILM requires custom attributes on certificates.'] },
];
const fine: Record<System, Record<Scheme, string>> = {
    macos: { light: 'rgb(26, 116, 49)', dark: 'rgb(48, 209, 88)' },
    windows: { light: 'rgb(13, 114, 13)', dark: 'rgb(108, 203, 95)' },
};
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

async function open(
    page: Page,
    mount: (component: React.ReactElement) => Promise<Locator>,
    os: Platform,
    scheme: Scheme,
    story: Partial<React.ComponentProps<typeof AddToIlmStory>> = {},
) {
    await page.emulateMedia({ colorScheme: scheme, reducedMotion: 'reduce' });
    await page.setViewportSize({ width: 760, height: 720 });
    await page.evaluate((system) => {
        document.documentElement.dataset.os = system;
    }, os);
    await mount(<AddToIlmStory platform={os} certificates={certificates} adding={{ choices, results }} {...story} />);
    await page.getByRole('dialog').waitFor();
}

for (const os of ['macos', 'windows'] as const) {
    for (const scheme of ['light', 'dark'] as const) {
        test(`on ${os} in ${scheme} the dialog has its surface and the results use the colours of the tokens`, async ({ mount, page }) => {
            await open(page, mount, os, scheme);
            const dialog = page.getByRole('dialog', { name: 'Add 3 certificates to ILM' });
            await expect(dialog.getByText(`Private keys stay on this ${os === 'macos' ? 'Mac' : 'PC'}`)).toBeVisible();
            await expect(dialog.getByRole('group', { name: 'Certificates to add' }).getByRole('checkbox')).toHaveCount(3);
            await expect(dialog.getByLabel('Group')).toBeVisible();
            await expect(dialog.getByLabel('RA Profile')).toHaveAccessibleDescription(
                'With an RA Profile ILM manages the certificate and can renew it. Without one ILM only tracks it.',
            );
            const surface = await dialog.evaluate((element) => getComputedStyle(element).backgroundColor);
            expect(surface).toBe(surfaces[os][scheme]);

            await dialog.getByRole('button', { name: 'Add 3 to ILM' }).click();
            await expect(dialog.getByRole('list', { name: 'Results' }).getByRole('listitem')).toHaveText([
                'wifi-corpAdded',
                'vpn-clientAdded, not managed: ILM does not allow this RA Profile.',
                'Lab deviceNot added: ILM requires custom attributes on certificates.',
            ]);
            const colours = await dialog.evaluate((element) =>
                [...element.querySelectorAll('ul[aria-label] > li > div > span:last-child')].map((line) => getComputedStyle(line).color),
            );
            expect(colours).toEqual([fine[os][scheme], attention[os][scheme], bad[os][scheme]]);
            await expect(dialog.getByRole('button')).toHaveText(['Close']);
        });
    }
}

test('the order of the buttons follows the system', async ({ mount, page }) => {
    await open(page, mount, 'macos', 'light');
    await expect(page.getByRole('dialog').getByRole('button')).toHaveText(['Cancel', 'Add 3 to ILM']);
});

test('on Windows the confirming button comes first', async ({ mount, page }) => {
    await open(page, mount, 'windows', 'light');
    await expect(page.getByRole('dialog').getByRole('button')).toHaveText(['Add 3 to ILM', 'Cancel']);
});

test('without the listings there is no Group and no RA Profile', async ({ mount, page }) => {
    await open(page, mount, 'macos', 'dark', { adding: { choices: { groups: null, raProfiles: null }, results } });

    await expect(page.getByRole('dialog').getByRole('combobox')).toHaveCount(0);
    await expect(page.getByText('With an RA Profile')).toHaveCount(0);
});

test('Group and RA Profile offer None first and the keyboard alone chooses and adds', async ({ mount, page }) => {
    await open(page, mount, 'windows', 'light');
    await keyboardReady(page);

    const group = page.getByRole('combobox', { name: 'Group' });
    await expect(group.locator('option')).toHaveText(['None', 'Engineering', 'Operations']);
    await expect(page.getByRole('combobox', { name: 'RA Profile' }).locator('option')).toHaveText(['None', 'Client certificates']);
    await expect(page.getByRole('button', { name: 'Add 3 to ILM' })).toBeFocused();
    await page.keyboard.press('Space');

    await expect(page.getByRole('button', { name: 'Close' })).toBeFocused();
    await page.keyboard.press('Enter');
    await expect(page.getByRole('dialog')).toHaveCount(0);
});

test('unchecking certificates changes the count, and with none the button is off', async ({ mount, page }) => {
    await open(page, mount, 'macos', 'light');

    const boxes = page.getByRole('checkbox');
    await boxes.nth(0).uncheck();
    await expect(page.getByRole('button', { name: 'Add 2 to ILM' })).toBeEnabled();
    await boxes.nth(1).uncheck();
    await boxes.nth(2).uncheck();
    await expect(page.getByRole('button', { name: 'Add 0 to ILM' })).toBeDisabled();
});

test('while adding it shows progress and Escape does not close it', async ({ mount, page }) => {
    await open(page, mount, 'macos', 'light', { adding: { choices, results, delay: 1200 } });
    await keyboardReady(page);

    await page.getByRole('button', { name: 'Add 3 to ILM' }).click();
    const busy = page.getByRole('button', { name: 'Adding…' });
    await expect(busy).toBeDisabled();
    await expect(page.getByRole('button', { name: 'Cancel' })).toHaveCount(0);
    await page.keyboard.press('Escape');
    await expect(page.getByRole('dialog')).toBeVisible();

    await expect(page.getByRole('button', { name: 'Close' })).toBeVisible();
});

test('Escape and Cancel close it before anything is added', async ({ mount, page }) => {
    await open(page, mount, 'windows', 'dark');
    await keyboardReady(page);

    await page.keyboard.press('Escape');
    await expect(page.getByRole('dialog')).toHaveCount(0);

    await page.getByRole('button', { name: 'Open' }).click();
    await page.getByRole('button', { name: 'Cancel' }).click();
    await expect(page.getByRole('dialog')).toHaveCount(0);
});

test('a refusal from the command is said in words and the person can try again', async ({ mount, page }) => {
    await open(page, mount, 'macos', 'light', { adding: { choices, refuse: 'ILM cannot be reached.' } });

    await page.getByRole('button', { name: 'Add 3 to ILM' }).click();

    await expect(page.getByRole('alert')).toHaveText('ILM cannot be reached.');
    await expect(page.getByRole('button', { name: 'Add 3 to ILM' })).toBeEnabled();
});

test('the page behind the dialog cannot take the focus', async ({ mount, page }) => {
    await open(page, mount, 'macos', 'light');
    await keyboardReady(page);

    await page.getByRole('button', { name: 'Open' }).focus();

    await expect(page.getByRole('button', { name: 'Open' })).not.toBeFocused();
    await expect(page.getByRole('button', { name: 'Add 3 to ILM' })).toBeFocused();
});
