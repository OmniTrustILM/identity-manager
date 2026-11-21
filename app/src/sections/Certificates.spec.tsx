import { clearMocks, mockIPC } from '@tauri-apps/api/mocks';
import { emit } from '@tauri-apps/api/event';
import { act } from 'react';
import { createRoot, type Root } from 'react-dom/client';
import { afterEach, beforeEach, expect, test, vi } from 'vitest';
import { AppInfoContext } from '../app-info';
import { IlmWaitingContext } from '../ilm-waiting';
import { ilmCertificate, inventory as checkedInventory } from '../../playwright/ilm';
import type { InventoryView, LocalCertificateView, Platform, SummaryView } from '../bridge';
import { NavigationContext } from '../navigation';
import { strings } from '../strings';
import { Certificates } from './Certificates';

const now = new Date(2026, 5, 21, 10, 0, 0).getTime();
const day = 24 * 60 * 60 * 1000;
const at = (days: number) => now + days * day;

const view = (name: string, over: Partial<LocalCertificateView> = {}): LocalCertificateView => ({
    fingerprint: `FP:${name}`,
    name,
    subject: `CN=${name},O=Demo`,
    issuer: 'CN=Demo Issuing CA',
    issuerName: 'Demo Issuing CA',
    serial: '5E:2B:9A',
    notBefore: at(-100),
    notAfter: at(212),
    uses: [{ kind: 'clientAuth' }],
    alternativeNames: [],
    key: { kind: 'rsa', value: { bits: 2048 } },
    location: 'keychain',
    canSignIn: true,
    signInProblem: null,
    ...over,
});

let container: HTMLElement;
let root: Root;
let requests: number;

beforeEach(() => {
    (globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true;
    vi.useFakeTimers({ toFake: ['Date', 'setTimeout', 'clearTimeout'] });
    vi.setSystemTime(now);
    container = document.createElement('div');
    document.body.append(container);
    root = createRoot(container);
    requests = 0;
});

afterEach(async () => {
    await act(async () => root.unmount());
    container.remove();
    clearMocks();
    vi.useRealTimers();
});

function answer(handler: () => unknown, others: (command: string, args: unknown) => unknown = () => undefined) {
    mockIPC((command, args) => {
        if (command === 'local_certificates') {
            requests += 1;
            return handler();
        }
        return others(command, args);
    });
}

const render = (platform: Platform = 'macos') =>
    act(async () =>
        root.render(
            <AppInfoContext.Provider value={{ name: 'Identity Manager', version: '1', platform }}>
                <Certificates />
            </AppInfoContext.Provider>,
        ),
    );

const options = () => [...container.querySelectorAll<HTMLElement>('[role="option"]')];
const detail = () => container.querySelector('section') as HTMLElement;
const selected = () => options().find((option) => option.getAttribute('aria-selected') === 'true');
const advance = (ms: number) => act(async () => vi.advanceTimersByTimeAsync(ms));
const key = (name: string) =>
    act(async () => {
        (document.activeElement as HTMLElement).dispatchEvent(new KeyboardEvent('keydown', { key: name, bubbles: true }));
    });
const focusEvent = () => act(async () => void window.dispatchEvent(new Event('focus')));
const visible = () => act(async () => void document.dispatchEvent(new Event('visibilitychange')));

test('lists the certificates in the order received with their uses, key locations and status', async () => {
    answer(() => [
        view('Zed', { uses: [], location: 'smartCard' }),
        view('Alpha', { uses: [{ kind: 'clientAuth' }, { kind: 'serverAuth' }], location: 'unknown', notAfter: at(0.2) }),
        view('Mid', { uses: [{ kind: 'other', value: '1.2.3' }, { kind: 'any' }], location: 'secureEnclave', notAfter: at(1) }),
        view('Soft', { location: 'software', notAfter: at(2) }),
        view('Chip', {
            location: 'tpm',
            notAfter: at(-5),
            uses: [{ kind: 'codeSigning' }, { kind: 'timeStamping' }, { kind: 'ocspSigning' }],
        }),
        view('Later', { notBefore: at(163), notAfter: at(300), uses: [{ kind: 'emailProtection' }] }),
    ]);
    await render();

    expect(options().map((option) => option.textContent)).toEqual([
        `Zed${strings.anyPurpose}${strings.locationLabels.smartCard}Expires in 212 days`,
        'AlphaClient authentication, Server authenticationCertificate storeExpires today',
        'Mid1.2.3, Any purposeSecure EnclaveExpires tomorrow',
        'SoftClient authenticationSoftwareExpires in 2 days',
        `ChipCode signing, Time stamping, OCSP signingTPMExpired ${strings.date(at(-5))}`,
        `LaterEmail protectionKeychainValid from ${strings.date(at(163))}`,
    ]);
    expect(container.querySelector('h1')?.textContent).toBe('Certificates');
    expect(container.textContent).toContain('6 on this Mac');
    expect(container.textContent).toContain(strings.certificateHeader + strings.privateKeyHeader + strings.statusHeader);
    expect(options()[4]?.querySelector('.text-bad')?.textContent).toContain('Expired');
});

test('the subline says PC on Windows', async () => {
    answer(() => [view('A')]);
    await render('windows');

    expect(container.textContent).toContain('1 on this PC');
});

test('options form a listbox named by certificate, use, key location and status, with one tab stop', async () => {
    answer(() => [view('First'), view('Second', { location: 'smartCard' })]);
    await render();

    const list = container.querySelector('[role="listbox"]');
    expect(list?.getAttribute('aria-label')).toBe(strings.certificatesListLabel);
    expect(options().map((option) => option.getAttribute('aria-label'))).toEqual([
        'First, Client authentication, Keychain, Expires in 212 days',
        'Second, Client authentication, Smart card, Expires in 212 days',
    ]);
    expect(options().map((option) => option.tabIndex)).toEqual([0, -1]);
});

test('the first row is selected and the detail shows its groups', async () => {
    answer(() => [
        view('CLIENT1', {
            alternativeNames: ['client1@demo.example', 'client1.demo.example'],
            key: { kind: 'ec', value: { curve: 'P-256' } },
            fingerprint: Array.from({ length: 32 }, (_, index) => index.toString(16).padStart(2, '0').toUpperCase()).join(':'),
        }),
        view('Other'),
    ]);
    await render();

    expect(selected()?.textContent).toContain('CLIENT1');
    const text = detail().textContent;
    expect(detail().querySelector('h2')?.textContent).toBe('CLIENT1');
    for (const part of [
        'Expires in 212 days',
        'CertificateValid from',
        'Demo Issuing CA',
        '5E:2B:9A',
        'UseAllowed forClient authenticationSign inCan sign in to ILM',
        'Private keyLocationKeychainAlgorithmECDSA P-256',
        'NamesSubjectCN=CLIENT1,O=DemoAlternative namesclient1@demo.example, client1.demo.example',
        'Fingerprint (SHA-256)',
    ]) {
        expect(text).toContain(part);
    }
    const lines = [...detail().querySelectorAll('[data-fingerprint] span')].map((line) => line.textContent);
    expect(lines).toHaveLength(2);
    expect(lines[0]?.split(':')).toHaveLength(16);
    expect(lines.join(':').split(':')).toHaveLength(32);
});

test.each([
    [{ kind: 'rsa', value: { bits: 3072 } } as const, 'RSA 3072'],
    [{ kind: 'ec', value: { curve: 'P-384' } } as const, 'ECDSA P-384'],
    [{ kind: 'ed25519' } as const, 'Ed25519'],
    [{ kind: 'other', value: '1.3.101.113' } as const, '1.3.101.113'],
])('shows the algorithm %j as %s', async (key_, label) => {
    answer(() => [view('A', { key: key_ })]);
    await render();

    expect(detail().textContent).toContain(`Algorithm${label}`);
});

test('the sign-in row shows the problem in red in a readable form', async () => {
    answer(() => [
        view('A', { canSignIn: false, signInProblem: 'is not for client authentication' }),
        view('B', { canSignIn: false, signInProblem: 'has a strange key' }),
    ]);
    await render();

    expect(detail().textContent).toContain('Sign inNot for client authentication');
    expect(detail().querySelector('.text-bad')?.textContent).toBe('Not for client authentication');
    await act(async () => options()[1]?.click());
    expect(detail().textContent).toContain('Sign inThis certificate has a strange key');
});

test('leaves out the alternative names when there are none', async () => {
    answer(() => [view('A')]);
    await render();

    expect(detail().textContent).not.toContain('Alternative names');
});

test('clicking a row selects it and the detail follows', async () => {
    answer(() => [view('A'), view('B', { notAfter: at(40) })]);
    await render();

    await act(async () => options()[1]?.click());

    expect(selected()?.textContent).toContain('B');
    expect(detail().querySelector('h2')?.textContent).toBe('B');
    expect(options().map((option) => option.tabIndex)).toEqual([-1, 0]);
});

test('arrows, Home and End move the selection and the focus', async () => {
    answer(() => [view('A'), view('B'), view('C')]);
    await render();
    options()[0]?.focus();

    await key('ArrowDown');
    expect(document.activeElement).toBe(options()[1]);
    expect(selected()).toBe(options()[1]);
    await key('End');
    expect(selected()).toBe(options()[2]);
    await key('ArrowDown');
    expect(selected()).toBe(options()[2]);
    await key('ArrowUp');
    expect(selected()).toBe(options()[1]);
    await key('Home');
    expect(selected()).toBe(options()[0]);
    await key('Tab');
    expect(selected()).toBe(options()[0]);
});

test('an empty list says there are no certificates with a key', async () => {
    answer(() => []);
    await render('windows');

    expect(container.textContent).toContain('No certificates with a private key on this PC.');
    expect(container.querySelector('[role="listbox"]')).toBeNull();
});

test('a failure shows the message and Try again asks again', async () => {
    let fail = true;
    answer(() => (fail ? Promise.reject('Unlock Identity Manager first.') : [view('A')]));
    await render();

    expect(container.querySelector('[role="alert"]')?.textContent).toContain('Unlock Identity Manager first.');
    expect(container.textContent).not.toContain('on this Mac');
    fail = false;
    await act(async () => (container.querySelector('button') as HTMLButtonElement).click());

    expect(requests).toBe(2);
    expect(options()).toHaveLength(1);
});

test('a failure without a message shows a general one', async () => {
    answer(() => Promise.reject(''));
    await render();

    expect(container.querySelector('[role="alert"]')?.textContent).toContain(strings.certificatesLoadFailed);
});

test('focus and visibility ask again, at most once in 2 seconds', async () => {
    answer(() => [view('A')]);
    await render();
    expect(requests).toBe(1);

    await advance(2000);
    await focusEvent();
    expect(requests).toBe(2);

    await advance(500);
    await visible();
    await focusEvent();
    expect(requests).toBe(2);
    await advance(1500);
    expect(requests).toBe(3);

    await advance(5000);
    expect(requests).toBe(3);
});

test('leaving the section stops the listeners and the pending request', async () => {
    answer(() => [view('A')]);
    await render();
    await focusEvent();
    await act(async () => root.unmount());
    await advance(5000);
    await focusEvent();

    expect(requests).toBe(1);
    root = createRoot(container);
});

test('an answer that is not the latest is dropped', async () => {
    let release: (items: LocalCertificateView[]) => void = () => undefined;
    const slow = new Promise<LocalCertificateView[]>((resolve) => {
        release = resolve;
    });
    const replies = [slow, Promise.resolve([view('Newer')])];
    answer(() => replies.shift());
    await render();
    await advance(2000);
    await focusEvent();
    expect(options().map((option) => option.getAttribute('aria-label')?.split(',')[0])).toEqual(['Newer']);

    await act(async () => release([view('Older'), view('Stale')]));

    expect(options().map((option) => option.getAttribute('aria-label')?.split(',')[0])).toEqual(['Newer']);
});

test('a refresh that fails replaces the list with the error', async () => {
    const replies = [() => Promise.resolve([view('A')]), () => Promise.reject('Cannot read the keychain.')];
    answer(() => replies.shift()?.());
    await render();
    await advance(2000);
    await focusEvent();

    expect(container.querySelector('[role="alert"]')?.textContent).toContain('Cannot read the keychain.');
    expect(options()).toHaveLength(0);
});

test('the selection stays on the same certificate when the list changes, else the first', async () => {
    const replies = [
        [view('A'), view('B'), view('C')],
        [view('Z'), view('A'), view('B'), view('C')],
        [view('Y'), view('A')],
    ];
    answer(() => replies.shift());
    await render();
    await act(async () => options()[1]?.click());
    expect(selected()?.textContent).toContain('B');

    await advance(2000);
    await focusEvent();
    expect(options()).toHaveLength(4);
    expect(selected()?.textContent).toContain('B');

    await advance(2000);
    await focusEvent();
    expect(selected()?.textContent).toContain('Y');
});

test('the first certificate shown stays shown when a refresh puts another before it', async () => {
    const replies = [
        [view('B'), view('C')],
        [view('A'), view('B'), view('C')],
    ];
    answer(() => replies.shift());
    await render();
    expect(selected()?.textContent).toContain('B');

    await advance(2000);
    await focusEvent();
    expect(options()).toHaveLength(3);
    expect(selected()?.textContent).toContain('B');
});

const mine = view('CLIENT1', { fingerprint: 'FP:one' });
const other = view('Alex Novak', { fingerprint: 'FP:two' });
const managed = ilmCertificate('CLIENT1', { raProfile: { uuid: 'ra', name: 'Client certificates' } });
const plain = ilmCertificate('Alex');
const everything = ['FP:one', 'FP:two', 'FP:three'];
const inventory = (over: Partial<InventoryView> = {}) => checkedInventory({ checked: everything, ...over });

function withInventory(current: InventoryView | null, extra: (command: string, args: unknown) => unknown = () => undefined) {
    answer(
        () => [mine, other, view('Build server', { fingerprint: 'FP:three', notAfter: at(-30) })],
        (command, args) => (command === 'ilm_status' ? current : extra(command, args)),
    );
}
const text = () => container.textContent ?? '';
const button = (name: string) =>
    [...container.querySelectorAll<HTMLButtonElement>('button')].find(
        (candidate) => candidate.textContent === name || candidate.getAttribute('aria-label') === name,
    );

test('rows show what ILM knows with an icon and short text, and the header counts the ones in ILM', async () => {
    withInventory(inventory({ matches: { 'FP:one': managed, 'FP:two': plain } }));
    await render();

    expect(options().map((option) => option.getAttribute('aria-label'))).toEqual([
        'CLIENT1, Client authentication, Keychain, Expires in 212 days, Managed by ILM',
        'Alex Novak, Client authentication, Keychain, Expires in 212 days, In ILM',
        expect.stringMatching(/^Build server, Client authentication, Keychain, Expired .*, Not in ILM$/),
    ]);
    expect(options()[0]?.querySelector('[title]')?.getAttribute('title')).toBe('Managed by ILM through Client certificates');
    expect(options()[0]?.querySelector('.text-fine')?.textContent).toBe('Managed by ILM');
    expect(options()[2]?.querySelector('.text-tertiary')?.textContent).toBe('Not in ILM');
    expect(text()).toContain('3 on this Mac, 2 of them in ILM');
    expect(text()).toContain('Checked with ILM at');
});

test('a first check that failed without a snapshot shows no ILM line and no count', async () => {
    withInventory(
        inventory({ status: { state: 'offline', since: null, reason: 'down', unreachable: true }, checkedAt: null, checked: [] }),
    );
    await render();

    expect(options()[0]?.getAttribute('aria-label')).toBe('CLIENT1, Client authentication, Keychain, Expires in 212 days');
    expect(text()).toContain('3 on this Mac');
    expect(text()).not.toContain('of them in ILM');
    expect(text()).not.toContain('Not in ILM');
});

test('only a certificate the check looked up can be said to be missing from ILM', async () => {
    withInventory(inventory({ checked: ['FP:one', 'FP:two'], matches: { 'FP:one': managed } }));
    await render();

    const labels = options().map((option) => option.getAttribute('aria-label'));
    expect(labels[1]).toBe('Alex Novak, Client authentication, Keychain, Expires in 212 days, Not in ILM');
    expect(labels[2]).not.toContain('ILM');
    expect(options()[2]?.querySelector('.text-tertiary')).toBeNull();
    expect(text()).toContain('3 on this Mac, 1 of them in ILM');
});

test('the header says PC on Windows', async () => {
    withInventory(inventory());
    await render('windows');

    expect(text()).toContain('3 on this PC, 0 of them in ILM');
    expect(button('On this PC')).toBeDefined();
});

test('before the first check there is no ILM line and no count', async () => {
    withInventory(inventory({ status: { state: 'never' }, checkedAt: null, checked: [] }));
    await render();

    expect(options()[0]?.getAttribute('aria-label')).toBe('CLIENT1, Client authentication, Keychain, Expires in 212 days');
    expect(text()).toContain('3 on this Mac');
    expect(text()).not.toContain('of them in ILM');
    expect(text()).not.toContain('Checked with ILM');
    expect(text()).not.toContain('Managed by ILM');
    expect(text()).not.toContain('Not in ILM');
    expect(button('Sync now')).toBeDefined();
});

test('without the certificates listing there is no ILM part at all', async () => {
    withInventory(inventory({ listed: false, matches: { 'FP:one': managed } }));
    await render();

    expect(text()).not.toContain('Checked with ILM');
    expect(text()).not.toContain('of them in ILM');
    expect(text()).not.toContain('Not in ILM');
    expect(button('Sync now')).toBeUndefined();
    expect(container.querySelector('fieldset')).toBeNull();
});

test('before ILM status is known the local list stands alone', async () => {
    withInventory(null);
    await render();

    expect(text()).not.toContain('of them in ILM');
    expect(options()).toHaveLength(3);
});

test('offline says so, with the time of the snapshot or without it', async () => {
    withInventory(
        inventory({ status: { state: 'offline', since: now - 60_000, reason: 'down', unreachable: true }, matches: { 'FP:one': managed } }),
    );
    await render();

    expect(text()).toContain(strings.cannotReachIlmSince(now - 60_000));
    expect(options()[0]?.getAttribute('aria-label')).toContain('Managed by ILM');
    await act(async () => root.unmount());
    root = createRoot(container);

    withInventory(
        inventory({ status: { state: 'offline', since: null, reason: 'down', unreachable: true }, checkedAt: null, checked: [] }),
    );
    await render();

    expect(text()).toContain('Cannot reach ILM.');
    expect(text()).not.toContain('Shown as of');
});

test('while a check runs the line says so and Sync now is off; otherwise it asks for a check', async () => {
    let syncs = 0;
    withInventory(inventory({ checking: true }));
    await render();
    expect(text()).toContain('Checking ILM\u2026');
    expect(button('Sync now')?.disabled).toBe(true);
    await act(async () => root.unmount());
    root = createRoot(container);

    withInventory(inventory(), (command) => {
        syncs += command === 'sync_now' ? 1 : 0;
        return command === 'sync_now' ? inventory({ matches: { 'FP:one': managed } }) : undefined;
    });
    await render();
    await act(async () => button('Sync now')?.click());

    expect(syncs).toBe(1);
    expect(text()).toContain('3 on this Mac, 1 of them in ILM');
});

test('while the saved sign-in waits for ILM Sync now is off and the kept answer shows', async () => {
    withInventory(
        inventory({ matches: { 'FP:one': managed }, status: { state: 'offline', since: now, reason: 'down', unreachable: true } }),
    );
    await act(async () =>
        root.render(
            <AppInfoContext.Provider value={{ name: 'Identity Manager', version: '1', platform: 'macos' }}>
                <IlmWaitingContext.Provider value>
                    <Certificates />
                </IlmWaitingContext.Provider>
            </AppInfoContext.Provider>,
        ),
    );

    expect(button('Sync now')?.disabled).toBe(true);
    expect(options()[0]?.getAttribute('aria-label')).toContain('Managed by ILM');
});

test('a Sync now that fails says why under the header and the next successful sync clears it', async () => {
    let fail = true;
    withInventory(inventory(), (command) => {
        if (command === 'sync_now') {
            return fail ? Promise.reject('The certificate store could not be read.') : inventory();
        }
        return undefined;
    });
    await render();
    await act(async () => button('Sync now')?.click());

    expect(container.querySelector('[role="alert"]')?.textContent).toBe('The certificate store could not be read.');

    fail = false;
    await act(async () => button('Sync now')?.click());

    expect(container.querySelector('[role="alert"]')).toBeNull();
});

test('a change event reads the status again', async () => {
    let current = inventory();
    withInventory(null, (command) => (command === 'ilm_status' ? current : undefined));
    mockIPC(
        (command, args) => {
            if (command === 'local_certificates') {
                return [mine];
            }
            return command === 'ilm_status' ? current : args && undefined;
        },
        { shouldMockEvents: true },
    );
    await render();
    expect(text()).toContain('1 on this Mac, 0 of them in ILM');

    current = inventory({ matches: { 'FP:one': managed } });
    await act(async () => emit('inventory-changed'));

    expect(text()).toContain('1 on this Mac, 1 of them in ILM');
});

test('the status is read only once the window listens for changes', async () => {
    const listening: ((id: number) => void)[] = [];
    const commands: string[] = [];
    mockIPC((command) => {
        commands.push(command);
        if (command === 'plugin:event|listen') {
            return new Promise((resolve) => listening.push(resolve));
        }
        return command === 'local_certificates' ? [mine] : undefined;
    });

    await render();
    expect(commands).not.toContain('ilm_status');

    await act(async () => {
        for (const resolve of listening) {
            resolve(1);
        }
    });

    expect(commands).toContain('ilm_status');
});

test('the sign-in certificate is marked with a named key icon, in the list and in the detail', async () => {
    withInventory(inventory({ matches: { 'FP:one': managed }, signIn: 'FP:one' }));
    await render();

    const mark = options()[0]?.querySelector('[role="img"]');
    expect(mark?.getAttribute('aria-label')).toBe('Sign-in certificate');
    expect(mark?.getAttribute('title')).toBe('Sign-in certificate');
    expect(options()[0]?.getAttribute('aria-label')).toContain('Sign-in certificate');
    expect(options()[1]?.querySelector('[role="img"]')).toBeNull();
    expect(detail().textContent).toContain('Sign inYour sign-in certificate');
});

test('the detail has an In ILM group for a managed, an unmanaged and an unknown certificate', async () => {
    withInventory(
        inventory({ matches: { 'FP:one': managed, 'FP:two': ilmCertificate('Alex', { owner: null, validationStatus: 'expired' }) } }),
    );
    await render();

    expect(detail().textContent).toContain(
        'In ILMStateIssuedValidationValidManagementManaged by ILM through Client certificatesOwneralex.morgan',
    );
    expect(detail().querySelector('.text-fine')?.textContent).toBe('Valid');
    await act(async () => options()[1]?.click());
    expect(detail().textContent).toContain('In ILMStateIssuedValidationExpiredManagementIn ILM, not managed');
    expect(detail().textContent).not.toContain('Owner');
    await act(async () => options()[2]?.click());
    expect(detail().textContent).toContain('In ILMStateNot in ILM');
});

test('ILM codes of the states and validation are shown as words', async () => {
    withInventory(
        inventory({ matches: { 'FP:one': ilmCertificate('X', { state: 'pending_approval', validationStatus: 'not_checked' }) } }),
    );
    await render();

    expect(detail().textContent).toContain('StatePending approvalValidationNot checked');
});

const eligible = () => inventory({ matches: { 'FP:one': managed } });
const makeButton = () => button('Make this my sign-in certificate');

test.each([
    ['matches nothing in ILM', () => inventory()],
    ['is not issued', () => inventory({ matches: { 'FP:one': ilmCertificate('X', { state: 'revoked' }) } })],
    ['is archived', () => inventory({ matches: { 'FP:one': ilmCertificate('X', { archived: true }) } })],
    ['is already the sign-in certificate', () => ({ ...eligible(), signIn: 'FP:one' })],
    ['cannot be reached', () => ({ ...eligible(), status: { state: 'offline', since: now, reason: 'down', unreachable: true } as const })],
])('there is no button when the certificate %s', async (_name, current) => {
    withInventory(current());
    await render();

    expect(makeButton()).toBeUndefined();
});

test('there is no button when the certificate cannot sign in locally', async () => {
    answer(
        () => [view('CLIENT1', { fingerprint: 'FP:one', canSignIn: false, signInProblem: 'has expired' })],
        (command) => (command === 'ilm_status' ? eligible() : undefined),
    );
    await render();

    expect(makeButton()).toBeUndefined();
});

test('the button asks first and Cancel changes nothing', async () => {
    let asked = 0;
    withInventory(eligible(), (command) => {
        asked += command === 'make_sign_in_certificate' ? 1 : 0;
        return undefined;
    });
    await render();
    makeButton()?.focus();
    await act(async () => makeButton()?.click());

    const dialog = container.querySelector('dialog');
    expect(dialog?.querySelector('h2')?.textContent).toBe('Use CLIENT1 to sign in to ILM?');
    expect(dialog?.textContent).not.toContain('stops working');
    expect([...(dialog?.querySelectorAll('button') ?? [])].map((each) => each.textContent)).toEqual(['Cancel', 'Use this certificate']);
    await act(async () => button('Cancel')?.click());

    expect(container.querySelector('dialog')).toBeNull();
    expect(asked).toBe(0);
    expect(document.activeElement).toBe(makeButton());
});

test('the buttons of the question are in the order of Windows there', async () => {
    withInventory(eligible());
    await render('windows');
    await act(async () => makeButton()?.click());

    expect([...container.querySelectorAll('dialog button')].map((each) => each.textContent)).toEqual(['Use this certificate', 'Cancel']);
});

test('when there is a sign-in certificate today the question names it', async () => {
    withInventory({ ...eligible(), matches: { 'FP:one': managed, 'FP:two': plain }, signIn: 'FP:two' });
    await render();
    await act(async () => makeButton()?.click());

    expect(container.querySelector('dialog')?.textContent).toContain('Alex stops working for sign-in.');
});

test('Escape closes the question', async () => {
    withInventory(eligible());
    await render();
    await act(async () => makeButton()?.click());

    const use = container.querySelectorAll<HTMLButtonElement>('dialog button')[1];
    expect(document.activeElement).toBe(use);
    await act(async () => void container.querySelector('dialog')?.dispatchEvent(new Event('cancel', { cancelable: true })));

    expect(container.querySelector('dialog')).toBeNull();
});

test('Use this certificate asks the core, closes and shows the new state', async () => {
    const asked: unknown[] = [];
    withInventory(eligible(), (command, args) => {
        if (command === 'make_sign_in_certificate') {
            asked.push(args);
            return { ...eligible(), signIn: 'FP:one' };
        }
        return undefined;
    });
    await render();
    await act(async () => makeButton()?.click());
    await act(async () => button('Use this certificate')?.click());

    expect(asked).toEqual([{ fingerprint: 'FP:one' }]);
    expect(container.querySelector('dialog')).toBeNull();
    expect(makeButton()).toBeUndefined();
    expect(options()[0]?.querySelector('[role="img"]')?.getAttribute('aria-label')).toBe('Sign-in certificate');
});

test.each([
    ['ILM does not allow this.', 'ILM does not allow this.'],
    ['', strings.signInChangeFailed],
])('an error from ILM (%j) is shown under the button in words', async (reason, shown) => {
    withInventory(eligible(), (command) => (command === 'make_sign_in_certificate' ? Promise.reject(reason) : undefined));
    await render();
    await act(async () => makeButton()?.click());
    await act(async () => button('Use this certificate')?.click());

    expect(container.querySelector('dialog')).toBeNull();
    expect(detail().querySelector('[role="alert"]')?.textContent).toBe(shown);
    expect(makeButton()).toBeDefined();
});

test('the segmented control shows only with the listing and switches to the In ILM view', async () => {
    withInventory(eligible(), (command) =>
        command === 'ilm_certificates' ? { certificates: [plain], pageNumber: 1, totalPages: 1, totalItems: 1 } : undefined,
    );
    await render();

    expect(button('On this Mac')?.getAttribute('aria-pressed')).toBe('true');
    await act(async () => button('In ILM')?.click());

    expect(button('In ILM')?.getAttribute('aria-pressed')).toBe('true');
    expect(container.querySelector('[role="listbox"]')?.getAttribute('aria-label')).toBe('Certificates in ILM');
    expect(text()).toContain('1 certificates in ILM');
    await act(async () => button('On this Mac')?.click());
    expect(container.querySelector('[role="listbox"]')?.getAttribute('aria-label')).toBe(strings.certificatesListLabel);
});

const lab = view('Lab device', { fingerprint: 'FP:lab', issuerName: 'Demo Issuing CA', notAfter: at(300) });
const labOnly = ['FP:lab'];
const summaryWith = (attention: SummaryView['attention']): SummaryView => ({
    computedAt: now,
    checkedAt: now,
    listed: true,
    counts: { valid: 1, expiring: 1, expired: 0, notInIlm: 1 },
    attention,
    months: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
});

function withLab(
    current: InventoryView | null,
    extra: (command: string, args: unknown) => unknown = () => undefined,
    items: LocalCertificateView[] = [lab],
) {
    answer(
        () => items,
        (command, args) => (command === 'ilm_status' ? current : extra(command, args)),
    );
}
const addButton = () => button(strings.addToIlm);

test('the expiry text is in the attention colour within the warning days and expired stays bad', async () => {
    const soon = view('Soon', { fingerprint: 'FP:soon', notAfter: at(12) });
    const gone = view('Gone', { fingerprint: 'FP:gone', notAfter: at(-3) });
    const later = view('Later', { fingerprint: 'FP:later', notAfter: at(100) });
    withLab(
        null,
        (command) =>
            command === 'overview'
                ? summaryWith([{ kind: 'expiring', fingerprint: 'FP:soon', name: 'Soon', days: 12, on: at(12) }])
                : undefined,
        [later, soon, gone],
    );
    await render();

    const tones = options().map(
        (option) => option.querySelector('div.flex-col > span')?.className.match(/text-(secondary|attention-text|bad)$/)?.[0],
    );
    expect(tones).toEqual(['text-secondary', 'text-attention-text', 'text-bad']);

    await act(async () => options()[1]?.click());
    expect(detail().querySelector('header p')?.className).toContain('text-attention-text');
    await act(async () => options()[2]?.click());
    expect(detail().querySelector('header p')?.className).toContain('text-bad');
});

test('under In ILM a certificate ILM does not know has Add to ILM, which adds it and reports', async () => {
    const asked: unknown[] = [];
    withLab(inventory({ checked: labOnly }), (command, args) => {
        if (command === 'add_to_ilm_choices') {
            return { groups: null, raProfiles: null };
        }
        if (command === 'add_to_ilm') {
            asked.push(args);
            return [{ fingerprint: 'FP:lab', outcome: 'added', messages: [] }];
        }
    });
    await render();

    const groups = [...detail().querySelectorAll('section')].map((group) => group.querySelector('h3')?.textContent);
    expect(groups.slice(0, 2)).toEqual([strings.certificateGroupTitle, strings.inIlmGroupTitle]);
    expect(detail().children[3]).toBe(addButton());

    await act(async () => addButton()?.click());
    expect(container.querySelector('dialog h2')?.textContent).toBe(strings.addTitle(1));
    await act(async () => button(strings.addCount(1))?.click());

    expect(asked).toEqual([{ fingerprints: ['FP:lab'], group: null, raProfile: null }]);
    expect(container.querySelector('dialog')?.textContent).toContain(strings.added);
    await act(async () => button(strings.close)?.click());
    expect(container.querySelector('dialog')).toBeNull();
});

test('the dialog stays while it reports although the check makes ILM know the certificate', async () => {
    let current = inventory({ checked: labOnly });
    mockIPC(
        (command) => {
            switch (command) {
                case 'local_certificates':
                    return [lab];
                case 'ilm_status':
                    return current;
                case 'add_to_ilm_choices':
                    return { groups: null, raProfiles: null };
                case 'add_to_ilm':
                    current = inventory({ checked: labOnly, matches: { 'FP:lab': plain } });
                    return [{ fingerprint: 'FP:lab', outcome: 'added', messages: [] }];
            }
        },
        { shouldMockEvents: true },
    );
    await render();
    await act(async () => addButton()?.click());
    await act(async () => button(strings.addCount(1))?.click());
    await act(async () => emit('inventory-changed'));

    expect(addButton()).toBeUndefined();
    expect(container.querySelector('dialog')?.textContent).toContain(strings.added);
});

test.each([
    [
        'ILM cannot be reached',
        () => inventory({ checked: labOnly, status: { state: 'offline', since: now, reason: 'no route', unreachable: true } }),
    ],
    ['certificates are not listed', () => inventory({ checked: [], listed: false })],
    ['ILM knows the certificate', () => inventory({ checked: labOnly, matches: { 'FP:lab': plain } })],
    ['no check has looked at it', () => inventory({ checked: [] })],
])('there is no Add to ILM when %s', async (_, current) => {
    withLab(current());
    await render();

    expect(addButton()).toBeUndefined();
});

test('there is no Add to ILM while the saved sign-in waits for ILM', async () => {
    withLab(inventory({ checked: labOnly }));
    await act(async () =>
        root.render(
            <AppInfoContext.Provider value={{ name: 'Identity Manager', version: '1', platform: 'macos' }}>
                <IlmWaitingContext.Provider value>
                    <Certificates />
                </IlmWaitingContext.Provider>
            </AppInfoContext.Provider>,
        ),
    );

    expect(addButton()).toBeUndefined();
});

test('a certificate it was sent to is selected, also when another was selected, and the list of this computer shows', async () => {
    withLab(inventory({ checked: labOnly }), () => undefined, [mine, lab, other]);
    const show = (fingerprint: string, id: number) =>
        act(async () =>
            root.render(
                <AppInfoContext.Provider value={{ name: 'Identity Manager', version: '1', platform: 'macos' }}>
                    <NavigationContext.Provider value={{ showing: { fingerprint, id }, showCertificate: () => undefined }}>
                        <Certificates />
                    </NavigationContext.Provider>
                </AppInfoContext.Provider>,
            ),
        );

    await show('FP:lab', 1);
    expect(selected()?.textContent).toContain('Lab device');

    await show('FP:two', 2);
    expect(selected()?.textContent).toContain('Alex Novak');
});
