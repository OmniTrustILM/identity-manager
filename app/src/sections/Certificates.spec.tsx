import { clearMocks, mockIPC } from '@tauri-apps/api/mocks';
import { act } from 'react';
import { createRoot, type Root } from 'react-dom/client';
import { afterEach, beforeEach, expect, test, vi } from 'vitest';
import { AppInfoContext } from '../app-info';
import type { LocalCertificateView, Platform } from '../bridge';
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

function answer(handler: () => unknown) {
    mockIPC((command) => {
        if (command === 'local_certificates') {
            requests += 1;
            return handler();
        }
        return undefined;
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

test('options form a listbox named by certificate, use and status, with one tab stop', async () => {
    answer(() => [view('First'), view('Second')]);
    await render();

    const list = container.querySelector('[role="listbox"]');
    expect(list?.getAttribute('aria-label')).toBe(strings.certificatesListLabel);
    expect(options().map((option) => option.getAttribute('aria-label'))).toEqual([
        'First, Client authentication, Expires in 212 days',
        'Second, Client authentication, Expires in 212 days',
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
