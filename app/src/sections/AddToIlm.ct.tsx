import { expect, test } from '@playwright/experimental-ct-react';
import type { Locator, Page } from '@playwright/test';
import { keyboardReady } from '../../playwright/focus';
import { attributeField, attributeForm, controlFields, unsupportedForm } from '../../playwright/attributes';
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
    customAttributes: null,
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
    await open(page, mount, 'macos', 'dark', { adding: { choices: { groups: null, raProfiles: null, customAttributes: null }, results } });

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

test('a listing of the choices that fails says so and leaves only Cancel', async ({ mount, page }) => {
    await open(page, mount, 'macos', 'light', { adding: { refuseChoices: true } });

    await expect(page.getByRole('alert')).toHaveText('ILM did not answer. Try again later.');
    await expect(page.getByRole('dialog').getByRole('button')).toHaveText(['Cancel']);
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

const withForm = (form = attributeForm(controlFields)): AddChoicesView => ({ ...choices, customAttributes: form });

for (const os of ['macos', 'windows'] as const) {
    for (const scheme of ['light', 'dark'] as const) {
        test(`on ${os} in ${scheme} the form scrolls inside the dialog while the buttons stay in view and a problem has the colour of the tokens`, async ({
            mount,
            page,
        }) => {
            await open(page, mount, os, scheme, {
                adding: { choices: withForm(), results, problems: [{ name: 'owner', problem: { kind: 'required' } }] },
            });
            const dialog = page.getByRole('dialog');
            await expect(dialog.getByRole('heading', { name: 'Custom attributes' })).toBeAttached();

            const owner = dialog.getByRole('textbox', { name: 'Owner', exact: true });
            await owner.focus();
            await dialog.getByRole('textbox', { name: 'Description', exact: true }).focus();

            await expect(owner).toHaveAccessibleDescription(/Enter a value\./);
            const colour = await owner.evaluate((input) => getComputedStyle(input).borderTopColor);
            expect(colour).toBe(bad[os][scheme]);
            await expect(dialog.getByRole('button', { name: 'Add 3 to ILM' })).toBeDisabled();
            await expect(dialog.getByRole('button', { name: 'Cancel' })).toBeInViewport();
            const scrolls = await dialog.evaluate((element) => {
                const body = [...element.querySelectorAll('div')].find(
                    (item) => item.scrollHeight > item.clientHeight + 1 && getComputedStyle(item).overflowY === 'auto',
                );
                return { box: element.getBoundingClientRect().height <= window.innerHeight, scrolls: body !== undefined };
            });
            expect(scrolls).toEqual({ box: true, scrolls: true });
        });
    }
}

test('the form is sent with the values the person gave, and the add is not blocked by a form that is fine', async ({ mount, page }) => {
    const seen: { command: string; args: unknown }[] = [];
    await open(page, mount, 'macos', 'light', {
        adding: {
            choices: withForm(attributeForm([attributeField('owner', { label: 'Owner', required: true })])),
            results,
            seen: (command, args) => seen.push({ command, args }),
        },
    });
    const dialog = page.getByRole('dialog');

    await dialog.getByRole('textbox', { name: 'Owner', exact: true }).fill('Alex');
    const add = dialog.getByRole('button', { name: 'Add 3 to ILM' });
    await expect(add).toBeEnabled();
    await add.click();

    await expect(dialog.getByRole('list', { name: 'Results' })).toBeVisible();
    const sent = seen.find((entry) => entry.command === 'add_to_ilm')?.args as { form: unknown };
    expect(sent.form).toEqual({ id: 'form-1', values: { owner: { kind: 'text', value: 'Alex' } } });
});

test('a required attribute that cannot be shown keeps the add off and says what to do', async ({ mount, page }) => {
    const seen: string[] = [];
    await open(page, mount, 'windows', 'dark', {
        adding: { choices: withForm(unsupportedForm), results, seen: (command) => seen.push(command) },
    });
    const dialog = page.getByRole('dialog');

    await expect(dialog.getByText('This form needs ILM’s web interface.')).toBeVisible();
    await expect(dialog.getByRole('button', { name: 'Add 3 to ILM' })).toBeDisabled();
    await dialog.getByRole('button', { name: 'Open in ILM' }).click();

    await expect.poll(() => seen).toContain('open_in_ilm');
});

test('the problems the add came back with show on the fields and the form stays', async ({ mount, page }) => {
    await open(page, mount, 'macos', 'dark', {
        adding: {
            choices: withForm(attributeForm([attributeField('owner', { label: 'Owner' })])),
            results,
            refuseProblems: [{ name: 'owner', problem: { kind: 'pattern', message: 'Use a company name.' } }],
        },
    });
    const dialog = page.getByRole('dialog');
    await dialog.getByRole('textbox', { name: 'Owner', exact: true }).fill('x');

    await dialog.getByRole('button', { name: 'Add 3 to ILM' }).click();

    await expect(dialog.getByRole('alert').filter({ hasText: 'Some attributes need your attention.' })).toHaveCount(1);
    await expect(dialog.getByRole('textbox', { name: 'Owner', exact: true })).toHaveAccessibleDescription('Use a company name.');
    await expect(dialog.getByRole('button', { name: 'Cancel' })).toBeVisible();
});

test('Cancel closes the form, and without custom attributes nothing is left to close', async ({ mount, page }) => {
    const seen: { command: string; args: unknown }[] = [];
    await open(page, mount, 'macos', 'light', {
        adding: {
            choices: withForm(attributeForm([attributeField('owner', { label: 'Owner' })])),
            results,
            seen: (command, args) => seen.push({ command, args }),
        },
    });

    await page.getByRole('button', { name: 'Cancel' }).click();

    await expect
        .poll(() => seen.filter((entry) => entry.command === 'close_form'))
        .toEqual([{ command: 'close_form', args: { id: 'form-1' } }]);
    await expect(page.getByRole('dialog')).toHaveCount(0);
});
