import { clearMocks, mockIPC } from '@tauri-apps/api/mocks';
import { act } from 'react';
import { createRoot, type Root } from 'react-dom/client';
import { afterEach, beforeEach, expect, test } from 'vitest';
import type { AddChoicesView, AddResultView, LocalCertificateView } from '../bridge';
import { strings } from '../strings';
import { AddToIlm } from './AddToIlm';

const at = new Date(2027, 5, 12).getTime();
const certificate = (name: string, issuerName: string): LocalCertificateView => ({
    fingerprint: `FP:${name}`,
    name,
    subject: `CN=${name}`,
    issuer: `CN=${issuerName}`,
    issuerName,
    serial: '5E:2B:9A',
    notBefore: at - 1000,
    notAfter: at,
    uses: [],
    alternativeNames: [],
    key: { kind: 'rsa', value: { bits: 2048 } },
    location: 'keychain',
    canSignIn: true,
    signInProblem: null,
});

const wifi = certificate('wifi-corp', 'Example Issuing CA 2');
const vpn = certificate('vpn-client', 'Example Lab Root');
const lab = certificate('Lab device', 'Demo Issuing CA');
const three = [wifi, vpn, lab];
const both: AddChoicesView = {
    groups: [
        { uuid: 'g-eng', name: 'Engineering' },
        { uuid: 'g-ops', name: 'Operations' },
    ],
    raProfiles: [{ uuid: 'ra-client', name: 'Client certificates', authority: 'Demo CA' }],
};

let container: HTMLElement;
let root: Root;
let choices: AddChoicesView | 'refused' | 'later';
let release: (view: AddChoicesView) => void;
let result: AddResultView[] | string | 'later';
let finish: (results: AddResultView[]) => void;
let asked: unknown[];
let closed: number;

beforeEach(() => {
    (globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true;
    container = document.createElement('div');
    document.body.append(container);
    root = createRoot(container);
    choices = { groups: null, raProfiles: null };
    result = [];
    asked = [];
    closed = 0;
    mockIPC((command, args) => {
        if (command === 'add_to_ilm_choices') {
            if (choices === 'later') {
                return new Promise((resolve) => (release = resolve));
            }
            return choices === 'refused' ? Promise.reject('no') : choices;
        }
        if (command === 'add_to_ilm') {
            asked.push(args);
            if (result === 'later') {
                return new Promise((resolve) => (finish = resolve));
            }
            return typeof result === 'string' ? Promise.reject(result) : result;
        }
    });
});

afterEach(async () => {
    await act(async () => root.unmount());
    container.remove();
    clearMocks();
});

const render = (certificates = three, system: 'macos' | 'windows' = 'macos') =>
    act(async () => root.render(<AddToIlm certificates={certificates} system={system} onClose={() => (closed += 1)} />));

const dialog = () => container.querySelector('dialog') as HTMLDialogElement;
const buttons = () => [...dialog().querySelectorAll('button')].map((candidate) => candidate.textContent);
const button = (name: string) => [...dialog().querySelectorAll('button')].find((candidate) => candidate.textContent === name);
const boxes = () => [...dialog().querySelectorAll<HTMLInputElement>('input[type="checkbox"]')];
const selects = () => [...dialog().querySelectorAll('select')];
const choose = (select: HTMLSelectElement, value: string) =>
    act(async () => {
        select.value = value;
        select.dispatchEvent(new Event('change', { bubbles: true }));
    });
const toggle = (box: HTMLInputElement) => act(async () => box.click());

test('shows nothing until ILM has said what may be chosen', async () => {
    choices = 'later';
    await render();
    expect(container.querySelector('dialog')).toBeNull();

    await act(async () => release({ groups: null, raProfiles: null }));

    expect(dialog().open).toBe(true);
});

test('names the certificates with their issuer and expiry, all checked, and says the keys stay', async () => {
    await render();

    expect(dialog().querySelector('h2')?.textContent).toBe('Add 3 certificates to ILM');
    expect(dialog().getAttribute('aria-labelledby')).toBe(dialog().querySelector('h2')?.id);
    expect(boxes().map((box) => box.checked)).toEqual([true, true, true]);
    const rows = [...dialog().querySelectorAll('label')].map((label) => label.textContent);
    expect(rows).toEqual([
        `wifi-corp${'Example Issuing CA 2'}, expires ${strings.date(at)}`,
        `vpn-client${'Example Lab Root'}, expires ${strings.date(at)}`,
        `Lab device${'Demo Issuing CA'}, expires ${strings.date(at)}`,
    ]);
    expect(dialog().textContent).toContain('Private keys stay on this Mac');
    expect(dialog().querySelector('legend')?.textContent).toBe(strings.certificatesToAdd);
});

test('says PC on Windows, and certificate for one', async () => {
    await render([wifi], 'windows');

    expect(dialog().querySelector('h2')?.textContent).toBe('Add 1 certificate to ILM');
    expect(dialog().textContent).toContain('Private keys stay on this PC');
});

test('the button counts the checked certificates and is off when none is', async () => {
    await render();

    await toggle(boxes()[1] as HTMLInputElement);
    expect(button('Add 2 to ILM')).toBeDefined();
    await toggle(boxes()[1] as HTMLInputElement);
    expect(button('Add 3 to ILM')).toBeDefined();

    for (const box of boxes()) {
        await toggle(box);
    }
    expect((button('Add 0 to ILM') as HTMLButtonElement).disabled).toBe(true);
});

test('Cancel comes first on macOS, the confirming button first on Windows', async () => {
    await render(three, 'macos');
    expect(buttons()).toEqual([strings.cancel, 'Add 3 to ILM']);

    await act(async () => root.render(null));
    await render(three, 'windows');
    expect(buttons()).toEqual(['Add 3 to ILM', strings.cancel]);
});

test('the confirming button has the focus, and Cancel and Escape close the dialog', async () => {
    await render();
    expect(document.activeElement?.textContent).toBe('Add 3 to ILM');

    await act(async () => button(strings.cancel)?.click());
    expect(closed).toBe(1);

    await act(async () => {
        dialog().dispatchEvent(new Event('cancel', { cancelable: true }));
    });
    expect(closed).toBe(2);
});

test('shows a group and an RA Profile only when ILM lets the person list them', async () => {
    await render();
    expect(selects()).toHaveLength(0);
    expect(dialog().textContent).not.toContain(strings.raProfileHint);

    choices = { groups: both.groups, raProfiles: null };
    await act(async () => root.render(null));
    await render();
    expect(selects().map((select) => select.labels?.[0]?.textContent)).toEqual([strings.group]);

    choices = { groups: null, raProfiles: both.raProfiles };
    await act(async () => root.render(null));
    await render();
    expect(selects().map((select) => select.labels?.[0]?.textContent)).toEqual([strings.raProfile]);
});

test('Group and RA Profile offer None first, and the RA Profile says what it does', async () => {
    choices = both;
    await render();

    const [group, profile] = selects() as HTMLSelectElement[];
    expect([...(group as HTMLSelectElement).options].map((option) => option.textContent)).toEqual(['None', 'Engineering', 'Operations']);
    expect([...(profile as HTMLSelectElement).options].map((option) => option.textContent)).toEqual(['None', 'Client certificates']);
    expect((group as HTMLSelectElement).value).toBe('');
    expect(document.getElementById(profile?.getAttribute('aria-describedby') ?? '')?.textContent).toBe(strings.raProfileHint);
    expect(group?.getAttribute('aria-describedby')).toBeNull();
});

test('adds the checked certificates with the chosen group and RA Profile', async () => {
    choices = both;
    await render();
    await toggle(boxes()[1] as HTMLInputElement);
    const [group, profile] = selects() as HTMLSelectElement[];
    await choose(group as HTMLSelectElement, 'g-ops');
    await choose(profile as HTMLSelectElement, 'ra-client');

    await act(async () => button('Add 2 to ILM')?.click());

    expect(asked).toEqual([{ fingerprints: ['FP:wifi-corp', 'FP:Lab device'], group: 'g-ops', raProfile: 'ra-client' }]);
});

test('adds with no group and no RA Profile when none is chosen', async () => {
    choices = both;
    await render();

    await act(async () => button('Add 3 to ILM')?.click());

    expect(asked).toEqual([{ fingerprints: ['FP:wifi-corp', 'FP:vpn-client', 'FP:Lab device'], group: null, raProfile: null }]);
});

test('a refused listing of the choices leaves the dialog without them', async () => {
    choices = 'refused';
    await render();

    expect(dialog().querySelector('h2')).not.toBeNull();
    expect(selects()).toHaveLength(0);
});

test('while adding the button shows progress and nothing can be done or withdrawn', async () => {
    choices = both;
    result = 'later';
    await render();
    await act(async () => button('Add 3 to ILM')?.click());

    expect(buttons()).toEqual([strings.adding]);
    expect((button(strings.adding) as HTMLButtonElement).disabled).toBe(true);
    expect(selects().every((select) => select.disabled)).toBe(true);
    expect(dialog().querySelector('fieldset')?.disabled).toBe(true);
    expect(dialog().querySelector('svg')).not.toBeNull();
    await act(async () => {
        dialog().dispatchEvent(new Event('cancel', { cancelable: true }));
    });
    expect(closed).toBe(0);
    expect(dialog().open).toBe(true);

    await act(async () => finish([]));
    expect(buttons()).toEqual([strings.close]);
});

test('afterwards each certificate says how it fared, with one Close button that has the focus', async () => {
    result = [
        { fingerprint: 'FP:wifi-corp', outcome: 'added', messages: [] },
        { fingerprint: 'FP:vpn-client', outcome: 'addedNotManaged', messages: ['ILM does not allow this RA Profile.'] },
        { fingerprint: 'FP:Lab device', outcome: 'notAdded', messages: ['ILM requires custom attributes on certificates.', 'Try again.'] },
    ];
    await render();
    await act(async () => button('Add 3 to ILM')?.click());

    const items = [...dialog().querySelectorAll('ul[aria-label] > li')];
    expect(dialog().querySelector('ul[aria-label]')?.getAttribute('aria-label')).toBe(strings.addResults);
    expect(items.map((item) => item.textContent)).toEqual([
        'wifi-corpAdded',
        'vpn-clientAdded, not managed: ILM does not allow this RA Profile.',
        'Lab deviceNot added: ILM requires custom attributes on certificates. Try again.',
    ]);
    expect(
        items.map(
            (item) => item.querySelector('.text-fine, .text-attention, .text-bad')?.className.match(/text-(fine|attention|bad)/)?.[0],
        ),
    ).toEqual(['text-fine', 'text-attention', 'text-bad']);
    expect(dialog().querySelector('h2')?.textContent).toBe('Add 3 certificates to ILM');
    expect(buttons()).toEqual([strings.close]);
    expect(document.activeElement?.textContent).toBe(strings.close);

    await act(async () => button(strings.close)?.click());
    expect(closed).toBe(1);
});

test('a certificate that was in ILM already is said to be added, and reasons may be missing', async () => {
    result = [
        { fingerprint: 'FP:wifi-corp', outcome: 'alreadyInIlm', messages: [] },
        { fingerprint: 'FP:vpn-client', outcome: 'addedNotManaged', messages: [] },
        { fingerprint: 'FP:Lab device', outcome: 'notAdded', messages: [] },
        { fingerprint: 'FP:unknown', outcome: 'added', messages: [] },
    ];
    await render();
    await act(async () => button('Add 3 to ILM')?.click());

    expect([...dialog().querySelectorAll('ul[aria-label] > li')].map((item) => item.textContent)).toEqual([
        'wifi-corpAdded',
        'vpn-clientAdded, not managed',
        'Lab deviceNot added',
        'FP:unknownAdded',
    ]);
});

test.each([
    ['ILM cannot be reached.', 'ILM cannot be reached.'],
    ['', strings.addFailed],
])('an error from the command (%j) is said in words and the person can try again', async (reason, shown) => {
    result = reason;
    await render();
    await act(async () => button('Add 3 to ILM')?.click());

    expect(dialog().querySelector('[role="alert"]')?.textContent).toBe(shown);
    expect(button('Add 3 to ILM')).toBeDefined();
    expect(dialog().querySelector('fieldset')?.disabled).toBe(false);

    result = [];
    await act(async () => button('Add 3 to ILM')?.click());
    expect(dialog().querySelector('[role="alert"]')).toBeNull();
});

test('returns the focus to where it was when it closes', async () => {
    const opener = document.createElement('button');
    document.body.append(opener);
    opener.focus();
    await render();
    expect(document.activeElement).not.toBe(opener);

    await act(async () => root.render(null));

    expect(document.activeElement).toBe(opener);
    opener.remove();
});

test('a dialog that is gone before ILM answered does nothing', async () => {
    choices = 'later';
    await render();
    await act(async () => root.render(null));

    await act(async () => release(both));

    expect(container.querySelector('dialog')).toBeNull();
});
