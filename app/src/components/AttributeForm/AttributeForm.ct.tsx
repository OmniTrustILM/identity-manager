import { expect, test } from '@playwright/experimental-ct-react';
import type { Locator, Page } from '@playwright/test';
import { attributeField, attributeForm, controlFields, extensibleFields, issueForm, unsupportedForm } from '../../../playwright/attributes';
import { keyboardReady } from '../../../playwright/focus';
import { AttributeFormStory } from '../../../playwright/stories';
import type { AttributeFieldView, AttributeFormView, Platform } from '../../bridge';

type Scheme = 'light' | 'dark';
type Story = Partial<React.ComponentProps<typeof AttributeFormStory>>;

const bad: Record<'macos' | 'windows', Record<Scheme, string>> = {
    macos: { light: 'rgb(200, 16, 28)', dark: 'rgb(255, 130, 121)' },
    windows: { light: 'rgb(189, 38, 25)', dark: 'rgb(255, 153, 164)' },
};

async function open(
    page: Page,
    mount: (component: React.ReactElement) => Promise<Locator>,
    os: Platform,
    scheme: Scheme,
    story: Story = {},
) {
    await page.emulateMedia({ colorScheme: scheme, reducedMotion: 'reduce' });
    await page.setViewportSize({ width: 560, height: 1000 });
    await page.evaluate((system) => {
        document.documentElement.dataset.os = system;
    }, os);
    await mount(<AttributeFormStory platform={os} form={attributeForm(controlFields)} {...story} />);
}

const values = (page: Page) => page.getByTestId('values');
/** The form after a callback gave the field `name` these options and chose the last one. */
const answered = (before: AttributeFieldView[], name: string, names: string[], revision = 1): AttributeFormView =>
    attributeForm(
        before.map((candidate) =>
            candidate.name === name
                ? {
                      ...candidate,
                      options: names.map((label, index) => ({ key: `k${index}`, label })),
                      value: { kind: 'option', value: `k${names.length - 1}` },
                      changedAt: revision,
                      valueSetAt: revision,
                  }
                : candidate,
        ),
        { revision },
    );

for (const os of ['macos', 'windows'] as const) {
    for (const scheme of ['light', 'dark'] as const) {
        test(`on ${os} in ${scheme} a problem is said in words, tied to its control and in the colour of the tokens`, async ({
            mount,
            page,
        }) => {
            await open(page, mount, os, scheme, {
                problems: [
                    { name: 'owner', problem: { kind: 'required' } },
                    { name: 'count', problem: { kind: 'notInteger' } },
                ],
            });
            const owner = page.getByRole('textbox', { name: 'Owner', exact: true });
            const count = page.getByRole('textbox', { name: 'TestInt' });

            await expect(owner).not.toHaveAccessibleDescription(/Enter a value/);
            await owner.focus();
            await page.keyboard.press('Tab');
            await count.focus();
            await page.keyboard.type('4 2');
            await owner.focus();

            await expect(owner).toHaveAccessibleDescription(/Enter a value\./);
            await expect(owner).toHaveAttribute('aria-invalid', 'true');
            await expect(count).toHaveAccessibleDescription('From 1 to 99 Enter a whole number.');
            const colours = await page.evaluate(() => {
                const problem = [...document.querySelectorAll('p')].find((item) => item.textContent === 'Enter a whole number.');
                const input = document.querySelector('input[inputmode="numeric"]');
                return [problem && getComputedStyle(problem).color, input && getComputedStyle(input).borderTopColor];
            });
            expect(colours).toEqual([bad[os][scheme], bad[os][scheme]]);
        });
    }
}

test('every control has its role and its name, and the required ones say so', async ({ mount, page }) => {
    await open(page, mount, 'macos', 'light');

    for (const name of ['Description', 'TestInt', 'Threshold', 'Review date', 'Window start', 'Valid until', 'Script', 'Settings']) {
        await expect(page.getByRole('textbox', { name, exact: true })).toBeVisible();
    }
    await expect(page.getByLabel('API key')).toHaveAttribute('type', 'password');
    await expect(page.getByRole('textbox', { name: 'Owner', exact: true })).toHaveAttribute('aria-required', 'true');
    await expect(page.getByRole('textbox', { name: 'Owner', exact: true })).toHaveAccessibleDescription('Who looks after it.');
    await expect(page.getByRole('switch', { name: 'Notify owner' })).not.toBeChecked();
    await expect(page.getByRole('combobox', { name: 'Importance level' })).toHaveValue('');
    await expect(page.getByRole('combobox', { name: 'Validity' })).toHaveAttribute('aria-required', 'true');
    await expect(page.getByRole('group', { name: 'Department' }).getByRole('checkbox')).toHaveCount(3);
    await expect(page.getByRole('button', { name: 'Choose file…' })).toBeVisible();
    await expect(page.getByText('bash')).toBeVisible();
    await expect(page.getByText('Attributes marked with a lock are set by ILM.')).toBeVisible();
    await expect(page.getByRole('group', { name: 'Cost owner' })).toContainText('Alex Morgan');
    await expect(page.getByRole('img', { name: 'Set by ILM' })).toHaveCount(1);
    await expect(page.getByRole('heading', { name: 'Custom attributes' })).toBeVisible();
    await expect(page.getByTestId('ready')).toHaveText('ready');
});

test('the keyboard alone fills the text fields, the switch, the selects and the checkbox lists', async ({ mount, page }) => {
    await open(page, mount, 'windows', 'light');
    await keyboardReady(page);

    await page.getByRole('textbox', { name: 'Owner', exact: true }).focus();
    await page.keyboard.type('Alex');
    const secret = page.getByLabel('API key');
    await secret.focus();
    await page.keyboard.type('hunter22');
    await page.keyboard.press('Tab');
    await expect(page.getByRole('button', { name: 'Show' })).toBeFocused();
    await page.keyboard.press('Space');
    await expect(secret).toHaveAttribute('type', 'text');

    const toggle = page.getByRole('switch', { name: 'Notify owner' });
    await toggle.focus();
    await page.keyboard.press('Space');
    await expect(toggle).toBeChecked();

    const validity = page.getByRole('combobox', { name: 'Validity' });
    await validity.focus();
    await validity.selectOption({ label: 'High' });

    const high = page.getByRole('group', { name: 'Department' }).getByRole('checkbox', { name: 'High' });
    await high.focus();
    await page.keyboard.press('Space');
    await expect(high).toBeChecked();
    await page.keyboard.press('Tab');
    await expect(page.getByRole('group', { name: 'Department' }).getByRole('checkbox').first()).not.toBeFocused();

    const contacts = page.getByRole('textbox', { name: 'Add value to Contact emails' });
    await contacts.focus();
    await page.keyboard.type('dev@example.com');
    await page.keyboard.press('Enter');
    await expect(page.getByRole('checkbox', { name: 'dev@example.com' })).toBeChecked();

    await expect(values(page)).toContainText('"owner":{"kind":"text","value":"Alex"}');
    await expect(values(page)).toContainText('"notify":{"kind":"bool","value":true}');
    await expect(values(page)).toContainText('"validity":{"kind":"option","value":"k2"}');
    await expect(values(page)).toContainText('"added","value":{"kind":"text","value":"dev@example.com"}');
});

test('the date and time inputs give ILM the wall clock and the offset of this computer', async ({ mount, page }) => {
    await open(page, mount, 'macos', 'dark');

    await page.getByRole('textbox', { name: 'Valid until' }).fill('2026-12-01T08:00');
    await page.getByRole('textbox', { name: 'Review date' }).fill('2026-12-02');
    await page.getByRole('textbox', { name: 'Window start' }).fill('09:15');

    await expect(values(page)).toContainText(/"until":\{"kind":"dateTime","value":"2026-12-01T08:00:00\.000[+-]\d\d:\d\d"\}/);
    await expect(values(page)).toContainText('"review":{"kind":"date","value":"2026-12-02"}');
    await expect(values(page)).toContainText('"window":{"kind":"time","value":"09:15"}');
});

test('the file button opens the chooser from the keyboard and shows the name and size of the file', async ({ mount, page }) => {
    await open(page, mount, 'windows', 'dark');
    await keyboardReady(page);
    const chooser = page.getByRole('button', { name: 'Choose file…' });
    await chooser.focus();

    const [dialog] = await Promise.all([page.waitForEvent('filechooser'), page.keyboard.press('Enter')]);
    await dialog.setFiles({ name: 'client.csr', mimeType: 'text/plain', buffer: Buffer.from('a'.repeat(2400)) });

    await expect(page.getByText('client.csr', { exact: true })).toBeVisible();
    await expect(page.getByText('2.3 KB', { exact: true })).toBeVisible();
    await expect(values(page)).toContainText('"template":{"kind":"file","value":{"name":"client.csr","mime":"text/plain"');

    const [second] = await Promise.all([page.waitForEvent('filechooser'), chooser.click()]);
    await second.setFiles({ name: 'big.bin', mimeType: 'application/octet-stream', buffer: Buffer.alloc(1024 * 1024 + 1) });
    await expect(chooser).toHaveAccessibleDescription('Choose a file of at most 1 MiB.');
    await expect(values(page)).not.toContainText('"template"');
});

test('Remove is reached with the keyboard, clears the file and returns focus to the file button', async ({ mount, page }) => {
    await open(page, mount, 'windows', 'dark');
    await keyboardReady(page);
    const chooser = page.getByRole('button', { name: 'Choose file…' });
    await expect(page.getByRole('button', { name: /^Remove .* file$/ })).toHaveCount(0);
    await chooser.focus();

    const [dialog] = await Promise.all([page.waitForEvent('filechooser'), page.keyboard.press('Enter')]);
    await dialog.setFiles({ name: 'client.csr', mimeType: 'text/plain', buffer: Buffer.from('a'.repeat(2400)) });
    await expect(page.getByText('client.csr', { exact: true })).toBeVisible();

    await keyboardReady(page);
    await chooser.focus();
    await page.keyboard.press('Tab');
    const remove = page.getByRole('button', { name: /^Remove .* file$/ });
    await expect(remove).toBeFocused();
    await page.keyboard.press('Enter');

    await expect(page.getByText('client.csr', { exact: true })).toHaveCount(0);
    await expect(page.getByText('No file chosen')).toBeVisible();
    await expect(chooser).toBeFocused();
    await expect(remove).toHaveCount(0);
    await expect(values(page)).not.toContainText('"template"');
});

test('a required attribute that cannot be shown has its row and Open in ILM, and the form is not ready', async ({ mount, page }) => {
    const seen: string[] = [];
    await open(page, mount, 'macos', 'light', { form: unsupportedForm, seen: (command) => seen.push(command) });
    await keyboardReady(page);

    await expect(page.getByText('Cost center: Identity Manager cannot show this attribute.')).toBeVisible();
    await expect(page.getByTestId('ready')).toHaveText('not ready');
    const openIlm = page.getByRole('button', { name: 'Open in ILM' });
    await openIlm.focus();
    await page.keyboard.press('Enter');

    await expect.poll(() => seen).toContain('open_in_ilm');
});

test('the request and issue attributes of the demo profile are shown as groups, the common name locked', async ({ mount, page }) => {
    await open(page, mount, 'macos', 'light', { form: issueForm });

    await expect(page.getByRole('heading', { level: 3 })).toHaveText(['Request attributes', 'Issue attributes']);
    await expect(page.getByRole('group', { name: 'Common name' })).toContainText('device-01.demo.example');
    await expect(
        page.getByRole('group', { name: 'Subject alternative names' }).getByRole('checkbox', { name: 'device-01.demo.example' }),
    ).toBeChecked();
    await expect(page.getByRole('combobox', { name: 'Service entitlement' })).toHaveValue('k0');
    await expect(page.getByRole('textbox', { name: 'Email' })).toHaveAccessibleDescription('An address at example.com.');
    await expect(page.getByRole('textbox', { name: 'Extension' })).toBeVisible();
    await expect(page.getByTestId('ready')).toHaveText('ready');
});

test('a callback replaces the options of a list and chooses what it answers', async ({ mount, page }) => {
    const fields = [attributeField('cred', { label: 'Credential', kind: 'select', callback: { kind: 'onOpen' } })];
    await open(page, mount, 'macos', 'light', {
        form: attributeForm(fields),
        answers: { cred: [{ form: answered(fields, 'cred', ['Alpha', 'Beta']) }] },
    });

    const select = page.getByRole('combobox', { name: 'Credential' });
    await expect(select.locator('option')).toHaveText(['None', 'Alpha', 'Beta']);
    await expect(select).toHaveValue('k1');
    await expect(values(page)).toContainText('"cred":{"kind":"option","value":"k1"}');
});

test('a snapshot that comes after a newer one is ignored', async ({ mount, page }) => {
    const fields = [
        attributeField('a', { label: 'Server' }),
        attributeField('b', { label: 'Credential', kind: 'select', callback: { kind: 'onChange', value: ['a'] } }),
    ];
    await open(page, mount, 'windows', 'light', {
        form: attributeForm(fields),
        answers: { b: [{ form: answered(fields, 'b', ['Old'], 1), delay: 1500 }, { form: answered(fields, 'b', ['New'], 2) }] },
    });
    const server = page.getByRole('textbox', { name: 'Server' });
    const select = page.getByRole('combobox', { name: 'Credential' });

    await server.fill('x');
    await page.waitForTimeout(700);
    await server.fill('xy');

    await expect(select.locator('option')).toHaveText(['None', 'New'], { timeout: 3000 });
    await page.waitForTimeout(1500);
    await expect(select.locator('option')).toHaveText(['None', 'New']);
});

test('a cleared dependency clears the field that depended on it', async ({ mount, page }) => {
    const fields = [
        attributeField('a', {
            label: 'Authority',
            kind: 'select',
            options: [{ key: 'k0', label: 'Demo CA' }],
            value: { kind: 'option', value: 'k0' },
        }),
        attributeField('b', { label: 'RA Profile', kind: 'select', callback: { kind: 'onChange', value: ['a'] } }),
    ];
    const cleared = attributeForm(
        fields.map((candidate) => (candidate.name === 'b' ? { ...candidate, changedAt: 2, valueSetAt: 2 } : candidate)),
        { revision: 2 },
    );
    await open(page, mount, 'macos', 'dark', {
        form: attributeForm(fields),
        answers: { b: [{ form: answered(fields, 'b', ['Client']) }, { form: cleared }] },
    });
    const profile = page.getByRole('combobox', { name: 'RA Profile' });

    await expect(profile).toHaveValue('k0');
    await page.getByRole('combobox', { name: 'Authority' }).selectOption({ label: 'None' });

    await expect(profile).toHaveValue('', { timeout: 3000 });
    await expect(profile.locator('option')).toHaveText(['None']);
    await expect(values(page)).toHaveText('{}');
});

test('while the form is busy no control takes input', async ({ mount, page }) => {
    await open(page, mount, 'linux', 'light', { disabled: true });

    await expect(page.getByRole('textbox', { name: 'Owner', exact: true })).toBeDisabled();
    await expect(page.getByRole('switch', { name: 'Notify owner' })).toBeDisabled();
    await expect(page.getByRole('button', { name: 'Choose file…' })).toBeDisabled();
});

test('extensible lists take added numbers, dates and dates and times with the keyboard', async ({ mount, page }) => {
    await open(page, mount, 'windows', 'dark', { form: attributeForm(extensibleFields) });
    await keyboardReady(page);

    const number = page.getByRole('textbox', { name: 'Add value to Extensible List Number' });
    await number.focus();
    await page.keyboard.type('42');
    await page.keyboard.press('Enter');
    await expect(page.getByRole('combobox', { name: 'Extensible List Number' })).toHaveValue('added');
    await expect(page.getByRole('combobox', { name: 'Extensible List Number' }).locator('option')).toHaveText(['None', '1', '2', '42']);

    await page.getByRole('textbox', { name: 'Add value to Extensible List Date', exact: true }).fill('2026-02-03');
    await page.getByRole('button', { name: 'Add' }).nth(1).click();
    await page.getByRole('textbox', { name: 'Add value to Extensible List DateTime' }).fill('2026-12-01T08:00');
    await page.getByRole('button', { name: 'Add' }).nth(2).click();

    await expect(values(page)).toContainText('"number":{"kind":"added","value":{"kind":"integer","value":"42"}}');
    await expect(values(page)).toContainText('"day":{"kind":"added","value":{"kind":"date","value":"2026-02-03"}}');
    await expect(values(page)).toContainText(
        /"moment":\{"kind":"options","value":\[\{"kind":"added","value":\{"kind":"dateTime","value":"2026-12-01T08:00:00\.000[+-]\d\d:\d\d"/,
    );
    await expect(page.getByRole('checkbox', { name: /2026-12-01T08:00:00/ })).toBeChecked();
});
