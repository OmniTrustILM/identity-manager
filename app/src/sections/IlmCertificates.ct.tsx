import { expect, test } from '@playwright/experimental-ct-react';
import type { Locator, Page } from '@playwright/test';
import { keyboardReady } from '../../playwright/focus';
import { ilmCertificate, inventory, page as ilmPage } from '../../playwright/ilm';
import { CertificatesStory, type IlmAnswer } from '../../playwright/stories';
import type { LocalCertificateView, Platform } from '../bridge';

type Scheme = 'light' | 'dark';
type Extra = Partial<React.ComponentProps<typeof CertificatesStory>>;

const day = 24 * 60 * 60 * 1000;
const local: LocalCertificateView = {
    fingerprint: 'IL:CLIENT1',
    name: 'CLIENT1',
    subject: 'CN=CLIENT1',
    issuer: 'CN=Demo Issuing CA',
    issuerName: 'Demo Issuing CA',
    serial: '5E:2B',
    notBefore: Date.now() - 100 * day,
    notAfter: Date.now() + 212 * day,
    uses: [{ kind: 'clientAuth' }],
    alternativeNames: [],
    key: { kind: 'rsa', value: { bits: 2048 } },
    location: 'keychain',
    canSignIn: true,
    signInProblem: null,
};

const first = ilmPage(
    [
        ilmCertificate('CLIENT1', { raProfile: { uuid: 'ra', name: 'Client certificates' }, groups: ['Engineering'] }),
        ilmCertificate('api-gateway-01', { issuerName: 'Demo Server Sub CA' }),
        ilmCertificate('old-vpn', { archived: true, notAfter: Date.now() - 30 * day }),
    ],
    { totalItems: 161_193, totalPages: 3224 },
);
const second = ilmPage([ilmCertificate('Second page one'), ilmCertificate('Second page two')], {
    pageNumber: 2,
    totalPages: 3224,
    totalItems: 161_193,
});

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
    extra: Extra = {},
) {
    await page.emulateMedia({ colorScheme: scheme, reducedMotion: 'reduce' });
    await page.evaluate((system) => {
        document.documentElement.dataset.os = system;
    }, os);
    await mount(
        <CertificatesStory
            platform={os}
            certificates={[local]}
            width={1100}
            inventory={inventory({ firstPage: first })}
            pages={{ '1|': first, '2|': second, '1|gateway': ilmPage([ilmCertificate('api-gateway-01')]), '*': ilmPage([]) }}
            {...extra}
        />,
    );
    await page.getByRole('button', { name: 'In ILM' }).click();
}

const requests = (page: Page) => page.evaluate(() => window.ilmRequests);

for (const os of ['macos', 'windows'] as const) {
    for (const scheme of ['light', 'dark'] as const) {
        test(`on ${os} in ${scheme} the In ILM view shows rows with an expired one in red and the detail beside`, async ({
            mount,
            page,
        }) => {
            await open(page, mount, os, scheme);
            await page.getByRole('option').first().waitFor();

            const measured = await page.evaluate(() => {
                const expired = [...document.querySelectorAll('[role="option"] span')].find((span) =>
                    span.textContent?.startsWith('Expired'),
                );
                return {
                    surface: getComputedStyle(document.querySelector('main') as HTMLElement).backgroundColor,
                    expired: expired && getComputedStyle(expired).color,
                };
            });
            expect(measured).toEqual({ surface: surfaces[os][scheme], expired: bad[os][scheme] });
            await expect(page.getByText('161,193 certificates in ILM')).toBeVisible();
            await expect(page.getByText('1–3 of 161,193')).toBeVisible();
            await expect(page.getByRole('region', { name: 'CLIENT1' }).getByText('Engineering')).toBeVisible();
        });
    }
}

test('rows are named by certificate, issuer, state, expiry, whether it is here and whether it is archived', async ({ mount, page }) => {
    await open(page, mount, 'macos', 'light');

    await expect(page.getByRole('listbox', { name: 'Certificates in ILM' })).toBeVisible();
    await expect(page.getByRole('option', { name: 'CLIENT1, Demo Client Sub CA, Issued, Expires in 212 days, On this Mac' })).toBeVisible();
    await expect(page.getByRole('option', { name: /^old-vpn, .*, Issued, Expired .*, Archived$/ })).toBeVisible();
    await expect(page.getByRole('img', { name: 'On this Mac' })).toHaveCount(1);
    await expect(page.getByText('Archived', { exact: true })).toBeVisible();
});

test('on Windows the computer icon says On this PC', async ({ mount, page }) => {
    await open(page, mount, 'windows', 'dark');

    await expect(page.getByRole('img', { name: 'On this PC' })).toBeVisible();
});

test('the keyboard alone: one tab stop in the list, arrows, Home and End, the detail follows', async ({ mount, page }) => {
    await open(page, mount, 'macos', 'light');
    await keyboardReady(page);
    await page.getByRole('searchbox', { name: 'Search by name' }).focus();

    await page.keyboard.press('Tab');
    await expect(page.getByRole('option', { name: /^CLIENT1/ })).toBeFocused();
    await page.keyboard.press('ArrowDown');
    await expect(page.getByRole('option', { name: /^api-gateway-01/ })).toBeFocused();
    await expect(page.getByRole('region', { name: 'api-gateway-01' })).toBeVisible();
    await page.keyboard.press('End');
    await expect(page.getByRole('option', { name: /^old-vpn/ })).toBeFocused();
    await page.keyboard.press('Home');
    await expect(page.getByRole('option', { name: /^CLIENT1/ })).toBeFocused();
    await page.keyboard.press('Tab');
    await expect(page.getByRole('button', { name: 'Previous' })).toBeDisabled();
    await expect(page.getByRole('button', { name: 'Next' })).toBeFocused();
});

test('Next and Previous page through ILM', async ({ mount, page }) => {
    await open(page, mount, 'macos', 'light');
    await page.getByRole('button', { name: 'Next' }).click();

    await expect(page.getByRole('option', { name: /^Second page one/ })).toBeVisible();
    await expect(page.getByText('51–52 of 161,193')).toBeVisible();
    await expect(page.getByRole('button', { name: 'Previous' })).toBeEnabled();
    await page.getByRole('button', { name: 'Previous' }).click();
    await expect(page.getByRole('option', { name: /^CLIENT1/ })).toBeVisible();
});

test('the search runs on Enter at once and after a 400 ms pause, not on every key', async ({ mount, page }) => {
    await open(page, mount, 'windows', 'light');
    await expect(page.getByRole('option').first()).toBeVisible();
    const box = page.getByRole('searchbox', { name: 'Search by name' });

    await box.pressSequentially('gate', { delay: 50 });
    expect(await requests(page)).toEqual(['1|']);
    await expect.poll(() => requests(page)).toEqual(['1|', '1|gate']);

    await box.fill('gateway');
    await box.press('Enter');
    await expect.poll(() => requests(page)).toEqual(['1|', '1|gate', '1|gateway']);
    await expect(page.getByRole('option')).toHaveCount(1);
});

test('an answer to an older page is dropped', async ({ mount, page }) => {
    await open(page, mount, 'macos', 'dark', { delays: { '2|': 800 } });
    await expect(page.getByRole('option').first()).toBeVisible();
    await page.getByRole('button', { name: 'Next' }).click();
    const box = page.getByRole('searchbox', { name: 'Search by name' });
    await box.fill('gateway');
    await box.press('Enter');

    await expect(page.getByRole('option')).toHaveCount(1);
    await expect.poll(() => page.evaluate(() => window.ilmAnswered)).toContain('2|');
    await expect(page.getByRole('option')).toHaveCount(1);
    await expect(page.getByRole('option', { name: /^api-gateway-01/ })).toBeVisible();
});

test('an error shows a plain message and Try again asks again', async ({ mount, page }) => {
    const answers: IlmAnswer[] = [{ error: 'ILM does not allow this.' }, first];
    await open(page, mount, 'windows', 'light', { pages: { '1|': answers }, inventory: inventory() });

    await expect(page.getByRole('alert')).toContainText('ILM does not allow this.');
    await page.getByRole('button', { name: 'Try again' }).click();
    await expect(page.getByRole('alert')).toHaveCount(0);
    await expect(page.getByRole('option').first()).toBeVisible();
});

test('offline shows the first page that was kept, with a note, and search and paging are off', async ({ mount, page }) => {
    await open(page, mount, 'macos', 'dark', {
        inventory: inventory({ status: { state: 'offline', since: Date.now() - 3600_000, reason: 'down' }, firstPage: first }),
    });

    await expect(page.getByText(/^Search and paging need ILM\. Showing the first page from /)).toBeVisible();
    await expect(page.getByRole('option')).toHaveCount(3);
    await expect(page.getByRole('searchbox', { name: 'Search by name' })).toBeDisabled();
    await expect(page.getByRole('button', { name: 'Next' })).toBeDisabled();
    await expect(page.getByRole('button', { name: 'Previous' })).toBeDisabled();
    expect(await requests(page)).toEqual([]);
});
