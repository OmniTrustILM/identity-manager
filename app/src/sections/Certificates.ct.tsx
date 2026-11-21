import { expect, test } from '@playwright/experimental-ct-react';
import type { Locator, Page } from '@playwright/test';
import { keyboardReady } from '../../playwright/focus';
import { ilmCertificate, inventory, summary } from '../../playwright/ilm';
import { CertificatesStory, UnreachableStory } from '../../playwright/stories';
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
    macos: { light: 'rgb(200, 16, 28)', dark: 'rgb(255, 130, 121)' },
    windows: { light: 'rgb(189, 38, 25)', dark: 'rgb(255, 153, 164)' },
};

async function open(
    page: Page,
    mount: (component: React.ReactElement) => Promise<Locator>,
    os: Platform,
    scheme: Scheme,
    width = 1000,
    certificates = list,
    extra: Partial<React.ComponentProps<typeof CertificatesStory>> = {},
) {
    await page.emulateMedia({ colorScheme: scheme, reducedMotion: 'reduce' });
    await page.evaluate((system) => {
        document.documentElement.dataset.os = system;
    }, os);
    await mount(<CertificatesStory platform={os} certificates={certificates} width={width} {...extra} />);
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

const managed = ilmCertificate('CLIENT1', { raProfile: { uuid: 'ra', name: 'Client certificates' } });
const known = (over: Parameters<typeof inventory>[0] = {}) =>
    inventory({
        checked: list.map((certificate) => certificate.fingerprint),
        matches: { [list[0]!.fingerprint]: managed },
        signIn: list[0]!.fingerprint,
        ...over,
    });
const fine: Record<'macos' | 'windows', Record<Scheme, string>> = {
    macos: { light: 'rgb(26, 116, 49)', dark: 'rgb(48, 209, 88)' },
    windows: { light: 'rgb(13, 114, 13)', dark: 'rgb(108, 203, 95)' },
};

for (const os of ['macos', 'windows'] as const) {
    for (const scheme of ['light', 'dark'] as const) {
        test(`on ${os} in ${scheme} Managed by ILM is in the fine colour and Not in ILM is quieter`, async ({ mount, page }) => {
            await open(page, mount, os, scheme, 1000, list, { inventory: known() });
            await expect(page.getByText('Managed by ILM', { exact: true })).toBeVisible();

            const colours = await page.evaluate(() => {
                const colour = (text: string) => {
                    const found = [...document.querySelectorAll('[role="option"] span')].find((span) => span.textContent === text);
                    return found && getComputedStyle(found).color;
                };
                return {
                    managed: colour('Managed by ILM'),
                    absent: colour('Not in ILM'),
                    sizes: [...document.querySelectorAll('[role="option"] svg')].map((icon) => icon.getBoundingClientRect().width),
                };
            });
            expect(colours.managed).toBe(fine[os][scheme]);
            expect(colours.absent).not.toBe(colours.managed);
            expect(colours.sizes.every((size) => size === 13 || size === 16)).toBe(true);
        });
    }
}

test('the row of the sign-in certificate carries a key icon named Sign-in certificate', async ({ mount, page }) => {
    await open(page, mount, 'macos', 'light', 1000, list, { inventory: known() });

    await expect(page.getByRole('img', { name: 'Sign-in certificate' })).toHaveCount(1);
    await expect(page.getByRole('option', { name: /^CLIENT1.*Managed by ILM, Sign-in certificate$/ })).toBeVisible();
    await page.getByRole('img', { name: 'Sign-in certificate' }).hover();
    await expect(page.getByRole('img', { name: 'Sign-in certificate' })).toHaveAttribute('title', 'Sign-in certificate');
});

test('the header counts the certificates in ILM and says when ILM was asked', async ({ mount, page }) => {
    await open(page, mount, 'macos', 'light', 1000, list, { inventory: known() });

    await expect(page.getByText('3 on this Mac, 1 of them in ILM')).toBeVisible();
    await expect(page.getByText(/^Checked with ILM at /)).toBeVisible();
    await expect(page.getByRole('button', { name: 'Sync now' })).toBeEnabled();
    await expect(page.getByRole('group', { name: 'Certificates to show' }).getByRole('button')).toHaveText(['On this Mac', 'In ILM']);
});

test('while ILM is checked the header says so and Sync now is off', async ({ mount, page }) => {
    await open(page, mount, 'windows', 'light', 1000, list, { inventory: known({ checking: true }) });

    await expect(page.getByText('Checking ILM\u2026')).toBeVisible();
    await expect(page.getByRole('button', { name: 'Sync now' })).toBeDisabled();
    await expect(page.getByText('3 on this PC, 1 of them in ILM')).toBeVisible();
});

test('offline says ILM cannot be reached and keeps the last answers', async ({ mount, page }) => {
    await open(page, mount, 'macos', 'dark', 1000, list, {
        inventory: known({ status: { state: 'offline', since: Date.now() - 3600_000, reason: 'down', unreachable: true } }),
    });

    await expect(page.getByText(/^Cannot reach ILM\. Shown as of /)).toBeVisible();
    await expect(page.getByRole('option', { name: /Managed by ILM/ })).toBeVisible();
    await expect(page.getByRole('button', { name: 'Make this my sign-in certificate' })).toHaveCount(0);
});

test('before the first check and without the listing the local list stands alone', async ({ mount, page }) => {
    await open(page, mount, 'macos', 'light', 1000, list, { inventory: inventory({ status: { state: 'never' }, checkedAt: null }) });
    await expect(page.getByText('3 on this Mac', { exact: true })).toBeVisible();
    await expect(page.getByText('Not in ILM')).toHaveCount(0);
    await expect(page.getByRole('option').first()).toHaveAccessibleName(/^CLIENT1, Client authentication, Keychain, Expires in 212 days$/);
});

test('without the certificates listing there is no segmented control, no line and no sync', async ({ mount, page }) => {
    await open(page, mount, 'windows', 'light', 1000, list, { inventory: inventory({ listed: false }) });

    await expect(page.getByRole('group', { name: 'Certificates to show' })).toHaveCount(0);
    await expect(page.getByRole('button', { name: 'Sync now' })).toHaveCount(0);
    await expect(page.getByText('Not in ILM')).toHaveCount(0);
});

test('the detail has the In ILM group and, at the bottom, the button for a certificate ILM manages', async ({ mount, page }) => {
    const other = ilmCertificate('Other');
    await open(page, mount, 'macos', 'light', 1100, list, {
        inventory: known({ signIn: null, matches: { [list[0]!.fingerprint]: managed, [list[1]!.fingerprint]: other } }),
    });

    const detail = page.getByRole('region', { name: 'CLIENT1' });
    await expect(detail.getByRole('heading', { level: 3, name: 'In ILM' })).toBeVisible();
    await expect(detail.getByText('Managed by ILM through Client certificates')).toBeVisible();
    await expect(detail.getByRole('button', { name: 'Make this my sign-in certificate' })).toBeVisible();
    await page.getByRole('option', { name: /^Build server/ }).click();
    await expect(page.getByRole('region', { name: 'Build server' }).getByText('Not in ILM')).toBeVisible();
    await expect(page.getByRole('button', { name: 'Make this my sign-in certificate' })).toHaveCount(0);
});

for (const os of ['macos', 'windows'] as const) {
    test(`on ${os} the question has the buttons in the order of the system, names the old certificate and the keyboard works`, async ({
        mount,
        page,
    }) => {
        const other = ilmCertificate('Alex Novak');
        await open(page, mount, os, 'light', 1100, list, {
            inventory: known({ signIn: list[1]!.fingerprint, matches: { [list[0]!.fingerprint]: managed, [list[1]!.fingerprint]: other } }),
        });
        await keyboardReady(page);
        const open_ = page.getByRole('button', { name: 'Make this my sign-in certificate' });
        await open_.focus();
        await page.keyboard.press('Enter');

        const dialog = page.getByRole('dialog', { name: 'Use CLIENT1 to sign in to ILM?' });
        await expect(dialog).toBeVisible();
        await expect(dialog).toContainText('Alex Novak stops working for sign-in.');
        const names = await dialog.getByRole('button').allTextContents();
        expect(names).toEqual(os === 'macos' ? ['Cancel', 'Use this certificate'] : ['Use this certificate', 'Cancel']);
        await expect(dialog.getByRole('button', { name: 'Use this certificate' })).toBeFocused();
        await page.keyboard.press(os === 'macos' ? 'Shift+Tab' : 'Tab');
        await expect(dialog.getByRole('button', { name: 'Cancel' })).toBeFocused();
        await page.keyboard.press(os === 'macos' ? 'Tab' : 'Shift+Tab');
        await expect(dialog.getByRole('button', { name: 'Use this certificate' })).toBeFocused();
        await page.keyboard.press('Escape');
        await expect(dialog).toHaveCount(0);
        await expect(open_).toBeFocused();
    });
}

test('Use this certificate makes it the sign-in certificate', async ({ mount, page }) => {
    await open(page, mount, 'macos', 'dark', 1100, list, { inventory: known({ signIn: null }) });
    await page.getByRole('button', { name: 'Make this my sign-in certificate' }).click();
    await expect(page.getByRole('dialog')).not.toContainText('stops working');
    await page.getByRole('button', { name: 'Use this certificate' }).click();

    await expect(page.getByRole('dialog')).toHaveCount(0);
    await expect(page.getByRole('button', { name: 'Make this my sign-in certificate' })).toHaveCount(0);
    await expect(page.getByRole('img', { name: 'Sign-in certificate' })).toHaveCount(1);
});

test('an error from ILM is shown under the button in words', async ({ mount, page }) => {
    await open(page, mount, 'windows', 'dark', 1100, list, {
        inventory: known({ signIn: null }),
        refuseSignIn: 'ILM does not allow this.',
    });
    await page.getByRole('button', { name: 'Make this my sign-in certificate' }).click();
    await page.getByRole('button', { name: 'Use this certificate' }).click();

    await expect(page.getByRole('alert')).toHaveText('ILM does not allow this.');
    await expect(page.getByRole('dialog')).toHaveCount(0);
    await expect(page.getByRole('button', { name: 'Make this my sign-in certificate' })).toBeVisible();
});

test('the keyboard keeps one tab stop in the list with the ILM line in the option name', async ({ mount, page }) => {
    await open(page, mount, 'macos', 'light', 1100, list, { inventory: known() });
    await keyboardReady(page);

    await page.getByRole('button', { name: 'In ILM' }).focus();
    await page.keyboard.press('Tab');
    await expect(page.getByRole('option', { name: /^CLIENT1/ })).toBeFocused();
    await page.keyboard.press('ArrowDown');
    await expect(page.getByRole('option', { name: /^Alex Novak.*Not in ILM$/ })).toBeFocused();
});

test('the sync button spins only while checking', async ({ mount, page }) => {
    await open(page, mount, 'macos', 'light', 1000, list, { inventory: known({ checking: true }) });
    await page.emulateMedia({ reducedMotion: 'no-preference' });

    await expect(page.getByRole('button', { name: 'Sync now' }).locator('svg')).toHaveCSS('animation-name', 'spin');
});

const waiting = (os: Platform, scheme: Scheme, refuse?: string) =>
    async function mountWaiting({ mount, page }: { mount: (component: React.ReactElement) => Promise<Locator>; page: Page }) {
        await page.emulateMedia({ colorScheme: scheme, reducedMotion: 'reduce' });
        await page.evaluate((system) => {
            document.documentElement.dataset.os = system;
        }, os);
        await page.setViewportSize({ width: 1000, height: 600 });
        await mount(
            <UnreachableStory
                platform={os}
                refuse={refuse}
                certificates={list}
                inventory={inventory({
                    status: { state: 'offline', since: Date.now() - 3600_000, reason: 'ILM cannot be reached.', unreachable: true },
                    matches: {
                        [list[0]?.fingerprint ?? '']: ilmCertificate('CLIENT1', { raProfile: { uuid: 'ra', name: 'Client certificates' } }),
                    },
                    checked: list.map((each) => each.fingerprint),
                })}
            />,
        );
        await page.getByRole('button', { name: 'Certificates' }).click();
        await page.getByRole('option').first().waitFor();
    };

for (const os of ['macos', 'windows'] as const) {
    for (const scheme of ['light', 'dark'] as const) {
        test(`on ${os} in ${scheme} a sign-in that waits for ILM shows the banner over the kept answer`, async ({ mount, page }) => {
            await waiting(os, scheme)({ mount, page });

            const banner = page.getByRole('region', { name: 'Connection' });
            await expect(banner).toContainText('Cannot reach ILM.');
            await expect(banner).toContainText('https://ilm.example.com');
            await expect(banner).toContainText('The identity provider cannot be reached.');
            await expect(page.getByText(/^Cannot reach ILM\. Shown as of /)).toBeVisible();
            await expect(page.getByRole('option', { name: /Managed by ILM/ })).toBeVisible();
            await expect(page.getByRole('button', { name: 'Sync now' })).toBeDisabled();
            await expect(page.getByRole('button', { name: 'Make this my sign-in certificate' })).toHaveCount(0);
            await expect(page.getByRole('button', { name: 'Sign out' })).toBeVisible();
        });
    }
}

test('Sign out in the banner announces a refusal', async ({ mount, page }) => {
    await waiting('windows', 'light', 'Unlock Identity Manager first.')({ mount, page });

    await page.getByRole('button', { name: 'Sign out' }).click();

    await expect(page.getByRole('alert')).toHaveText('Unlock Identity Manager first.');
});

const attentionColour: Record<'macos' | 'windows', Record<Scheme, string>> = {
    macos: { light: 'rgb(201, 52, 0)', dark: 'rgb(255, 159, 10)' },
    windows: { light: 'rgb(157, 93, 0)', dark: 'rgb(252, 225, 0)' },
};
const soon = certificate('Soon', { notAfter: Date.now() + 12 * day });
const soonSummary = summary([{ kind: 'expiring', fingerprint: soon.fingerprint, name: 'Soon', days: 12, on: soon.notAfter }]);

for (const os of ['macos', 'windows'] as const) {
    for (const scheme of ['light', 'dark'] as const) {
        test(`on ${os} in ${scheme} the expiry within the warning days is in the colour of attention and expired stays red`, async ({
            mount,
            page,
        }) => {
            await open(page, mount, os, scheme, 1000, [certificate('Later'), soon, list[2]!], { summary: soonSummary });
            await expect(page.getByRole('option', { name: /^Soon/ })).toBeVisible();

            const colours = await page.evaluate(() => {
                const colour = (text: string) => {
                    const found = [...document.querySelectorAll('[role="option"] span')].find((span) => span.textContent?.startsWith(text));
                    return found && getComputedStyle(found).color;
                };
                return { soon: colour('Expires in 12'), later: colour('Expires in 212'), expired: colour('Expired') };
            });
            expect(colours.soon).toBe(attentionColour[os][scheme]);
            expect(colours.later).not.toBe(colours.soon);
            expect(colours.expired).toBe(bad[os][scheme]);
            await page.getByRole('option', { name: /^Soon/ }).click();
            await expect(page.getByRole('heading', { name: 'Soon', level: 2 }).locator('xpath=following-sibling::p')).toHaveCSS(
                'color',
                attentionColour[os][scheme],
            );
        });
    }
}

const unknown = certificate('Lab device');
const unknownInventory = (over: Parameters<typeof inventory>[0] = {}) => inventory({ checked: [unknown.fingerprint], ...over });

test('an unmatched certificate has Add to ILM under the In ILM group, which opens the dialog with it checked', async ({ mount, page }) => {
    await open(page, mount, 'macos', 'light', 1000, [unknown], { inventory: unknownInventory(), adding: { results: [] } });

    const detail = page.getByRole('region').filter({ has: page.getByRole('heading', { name: 'Lab device', level: 2 }) });
    const ilm = detail.getByRole('region', { name: 'In ILM' });
    await expect(ilm).toBeVisible();
    const [group, button] = await Promise.all([ilm.boundingBox(), page.getByRole('button', { name: 'Add to ILM' }).boundingBox()]);
    expect(button?.y).toBeGreaterThanOrEqual((group?.y ?? 0) + (group?.height ?? 0));

    await page.getByRole('button', { name: 'Add to ILM' }).click();

    const dialog = page.getByRole('dialog', { name: 'Add 1 certificate to ILM' });
    await expect(dialog.getByRole('checkbox', { name: /Lab device/ })).toBeChecked();
});

test('there is no Add to ILM when ILM cannot be reached', async ({ mount, page }) => {
    await open(page, mount, 'windows', 'dark', 1000, [unknown], {
        inventory: unknownInventory({ status: { state: 'offline', since: Date.now() - 60000, reason: 'no route', unreachable: true } }),
    });
    await expect(page.getByRole('heading', { name: 'Lab device', level: 2 })).toBeVisible();
    await expect(page.getByRole('button', { name: 'Add to ILM' })).toHaveCount(0);
});

test('the keyboard alone opens Add to ILM and closes it with Escape, returning the focus', async ({ mount, page }) => {
    await open(page, mount, 'macos', 'light', 1000, [unknown], { inventory: unknownInventory(), adding: { results: [] } });
    await keyboardReady(page);

    const add = page.getByRole('button', { name: 'Add to ILM' });
    await add.focus();
    await page.keyboard.press('Enter');
    await expect(page.getByRole('dialog')).toBeVisible();
    await page.keyboard.press('Escape');

    await expect(page.getByRole('dialog')).toHaveCount(0);
    await expect(add).toBeFocused();
});
