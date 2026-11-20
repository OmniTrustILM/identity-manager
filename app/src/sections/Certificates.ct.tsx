import { expect, test } from '@playwright/experimental-ct-react';
import type { Locator, Page } from '@playwright/test';
import { keyboardReady } from '../../playwright/focus';
import { CertificatesStory } from '../../playwright/stories';
import type { LocalCertificateView, Platform } from '../bridge';

type Scheme = 'light' | 'dark';

const day = 24 * 60 * 60 * 1000;
const certificate = (name: string, over: Partial<LocalCertificateView> = {}): LocalCertificateView => ({
    fingerprint: `${name.length.toString(16).padStart(2, '0')}:3F:9A:C1:07:5B:E2:48:D6:1C:A0:7E:93:2B:F5:60:8D:B4:19:E7:52:CA:36:0F:81:6D:A8:D3:44:9E:70:2C:F1`,
    name,
    subject: `CN=${name},OU=Engineering,O=Demo Org,C=CZ`,
    issuer: 'CN=Demo Issuing CA',
    issuerName: 'Demo Issuing CA',
    serial: '5E:2B:9A:01:7C:44:D3:18',
    notBefore: Date.now() - 100 * day,
    notAfter: Date.now() + 212 * day,
    uses: [{ kind: 'clientAuth' }],
    alternativeNames: ['client1@demo.example'],
    key: { kind: 'rsa', value: { bits: 2048 } },
    location: 'keychain',
    canSignIn: true,
    signInProblem: null,
    ...over,
});
const list = [
    certificate('CLIENT1'),
    certificate('Alex Novak', { uses: [{ kind: 'emailProtection' }], canSignIn: false, signInProblem: 'is not for client authentication' }),
    certificate('Build server', { notAfter: Date.now() - 30 * day, location: 'smartCard' }),
];

const surfaces: Record<'macos' | 'windows', Record<Scheme, string>> = {
    macos: { light: 'rgb(255, 255, 255)', dark: 'rgb(30, 30, 30)' },
    windows: { light: 'rgb(251, 251, 251)', dark: 'rgb(39, 39, 39)' },
};
const bad: Record<'macos' | 'windows', Record<Scheme, string>> = {
    macos: { light: 'rgb(255, 59, 48)', dark: 'rgb(255, 69, 58)' },
    windows: { light: 'rgb(196, 43, 28)', dark: 'rgb(255, 153, 164)' },
};

async function open(
    page: Page,
    mount: (component: React.ReactElement) => Promise<Locator>,
    os: Platform,
    scheme: Scheme,
    width = 1000,
    certificates = list,
) {
    await page.emulateMedia({ colorScheme: scheme, reducedMotion: 'reduce' });
    await page.evaluate((system) => {
        document.documentElement.dataset.os = system;
    }, os);
    await mount(<CertificatesStory platform={os} certificates={certificates} width={width} />);
    await page.getByRole('option').first().waitFor();
}

for (const os of ['macos', 'windows'] as const) {
    for (const scheme of ['light', 'dark'] as const) {
        test(`on ${os} in ${scheme} the section has its surface and shows an expired certificate in red`, async ({ mount, page }) => {
            await open(page, mount, os, scheme);

            const measured = await page.evaluate(() => {
                const main = document.querySelector('main') as HTMLElement;
                const expired = [...document.querySelectorAll('[role="option"] span')].find((span) =>
                    span.textContent?.startsWith('Expired'),
                );
                const selected = document.querySelector('[aria-selected="true"]') as HTMLElement;
                return {
                    surface: getComputedStyle(main).backgroundColor,
                    expired: expired && getComputedStyle(expired).color,
                    highlighted: getComputedStyle(selected).backgroundColor !== 'rgba(0, 0, 0, 0)',
                };
            });
            expect(measured).toEqual({ surface: surfaces[os][scheme], expired: bad[os][scheme], highlighted: true });
        });
    }
}

test('the keyboard alone reaches the list, moves the selection and the detail follows', async ({ mount, page }) => {
    await open(page, mount, 'macos', 'light');
    await keyboardReady(page);

    await page.keyboard.press('Tab');
    await expect(page.getByRole('option', { name: /^CLIENT1/ })).toBeFocused();
    await page.keyboard.press('ArrowDown');
    await expect(page.getByRole('option', { name: /^Alex Novak/ })).toBeFocused();
    await expect(page.getByRole('option', { name: /^Alex Novak/ })).toHaveAttribute('aria-selected', 'true');
    await expect(page.getByRole('heading', { level: 2, name: 'Alex Novak' })).toBeVisible();
    await expect(page.getByText('Not for client authentication')).toBeVisible();
    await page.keyboard.press('End');
    await expect(page.getByRole('option', { name: /^Build server/ })).toBeFocused();
    await page.keyboard.press('Home');
    await expect(page.getByRole('option', { name: /^CLIENT1/ })).toBeFocused();
    await page.keyboard.press('Tab');
    await expect(page.getByRole('option').first()).not.toBeFocused();
});

test('the list is a listbox whose options are named by certificate, use and status', async ({ mount, page }) => {
    await open(page, mount, 'windows', 'light');

    await expect(page.getByRole('listbox', { name: 'Certificates on this computer' })).toBeVisible();
    await expect(page.getByRole('option', { name: 'CLIENT1, Client authentication, Keychain, Expires in 212 days' })).toBeVisible();
    await expect(page.getByRole('option', { name: /^Build server, Client authentication, Smart card, Expired/ })).toBeVisible();
});

test('a focused row shows a focus ring', async ({ mount, page }) => {
    await open(page, mount, 'windows', 'dark');
    await keyboardReady(page);

    await page.keyboard.press('Tab');
    await expect(page.getByRole('option').first()).not.toHaveCSS('outline-style', 'none');
});

const placement = async (page: Page) => ({
    list: (await page.getByRole('listbox').boundingBox())!,
    detail: (await page.getByRole('heading', { level: 2, name: 'CLIENT1' }).boundingBox())!,
});

test('on a wide window the detail sits beside the list', async ({ mount, page }) => {
    await open(page, mount, 'macos', 'light', 1100);

    const { list, detail } = await placement(page);
    expect(detail.x).toBeGreaterThanOrEqual(list.x + list.width);
});

test('on a narrow window the detail sits below the list', async ({ mount, page }) => {
    await open(page, mount, 'macos', 'light', 560);

    const { list, detail } = await placement(page);
    expect(detail.y).toBeGreaterThanOrEqual(list.y + list.height);
});
