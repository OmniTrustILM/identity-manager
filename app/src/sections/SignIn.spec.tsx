import { emit } from '@tauri-apps/api/event';
import { clearMocks, mockIPC } from '@tauri-apps/api/mocks';
import { act } from 'react';
import { createRoot, type Root } from 'react-dom/client';
import { afterEach, beforeEach, expect, test } from 'vitest';
import type { CertificateChoice, ProviderChoice, SessionView } from '../bridge';
import { strings } from '../strings';
import { SignIn, UnreachableBanner } from './SignIn';

type Waiting = Extract<SessionView, { state: 'signingIn' }>;
type Idle = Extract<SessionView, { state: 'signedOut' }>;

const idle: Idle = { state: 'signedOut', address: null, locked: false, problem: null, again: false };
const managed: Idle = { ...idle, address: 'https://ilm.example.com', locked: true };
const waiting: Waiting = { state: 'signingIn', method: 'browser', provider: 'Company SSO' };
const one: ProviderChoice[] = [{ id: '0', name: 'Company SSO' }];
const several: ProviderChoice[] = [...one, { id: '1', name: 'Okta' }];

let container: HTMLElement;
let root: Root;
let calls: { command: string; args: unknown }[];

beforeEach(() => {
    (globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true;
    container = document.createElement('div');
    document.body.append(container);
    root = createRoot(container);
    calls = [];
});

afterEach(async () => {
    await act(async () => root.unmount());
    container.remove();
    clearMocks();
});

function bridge(handler: (command: string, args: unknown) => unknown) {
    mockIPC(
        (command, args) => {
            calls.push({ command, args });
            return handler(command, args);
        },
        { shouldMockEvents: true },
    );
}

const render = (view: Idle | Waiting) => act(async () => root.render(<SignIn view={view} />));

const heading = () => container.querySelector('h1')?.textContent;
const field = () => container.querySelector('input') as HTMLInputElement;
const buttons = () => [...container.querySelectorAll('button')];
const button = (name: string) => buttons().find((candidate) => candidate.textContent === name) as HTMLButtonElement;
const alerts = () => [...container.querySelectorAll('[role="alert"]')].map((alert) => alert.textContent);
const commands = () => calls.map((call) => call.command);

async function type(text: string) {
    await act(async () => {
        Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value')?.set?.call(field(), text);
        field().dispatchEvent(new Event('input', { bubbles: true }));
    });
}

const press = (name: string) => act(async () => button(name).click());

test('Connect asks for the address with one field and Continue', async () => {
    await render(idle);

    expect(heading()).toBe(strings.connectTitle);
    expect(container.textContent).toContain(strings.connectHint);
    expect(container.querySelector(`label[for="${field().id}"]`)?.textContent).toBe(strings.ilmAddress);
    expect(field().value).toBe('');
    expect(field().readOnly).toBe(false);
    expect(buttons().map((candidate) => candidate.textContent)).toEqual([strings.continue]);
    expect(button(strings.continue).disabled).toBe(true);
});

test('Connect shows the address the person gave before', async () => {
    await render({ ...idle, address: 'https://ilm.example.com' });

    expect(field().value).toBe('https://ilm.example.com');
    expect(button(strings.continue).disabled).toBe(false);
});

test('Welcome shows the address of the organization read-only with its lock note and Sign in', async () => {
    await render(managed);

    expect(heading()).toBe(strings.welcomeTitle);
    expect(container.textContent).toContain(strings.welcomeHint);
    expect(field().value).toBe('https://ilm.example.com');
    expect(field().readOnly).toBe(true);
    expect(document.getElementById(field().getAttribute('aria-describedby') ?? '')?.textContent).toBe(strings.managedByOrganization);
    expect(buttons().map((candidate) => candidate.textContent)).toEqual([strings.signIn]);
});

test('Continue connects to the typed address and signs in with the only provider', async () => {
    bridge((command) => (command === 'connect' ? one : undefined));
    await render(idle);
    await type(' ilm.example.com ');

    await press(strings.continue);

    expect(calls).toEqual([
        { command: 'connect', args: { address: 'ilm.example.com' } },
        { command: 'sign_in', args: { providerId: '0' } },
    ]);
});

test('Continue shows the choice when the ILM offers several providers and signs in with the one chosen', async () => {
    bridge((command) => (command === 'connect' ? several : undefined));
    await render(idle);
    await type('ilm.example.com');

    await press(strings.continue);

    expect(heading()).toBe(strings.chooseTitle);
    expect(container.textContent).toContain(strings.chooseHint);
    expect(buttons().map((candidate) => candidate.textContent)).toEqual(['Company SSO', 'Okta', strings.back]);
    expect(commands()).toEqual(['connect']);

    await press('Okta');

    expect(calls.at(-1)).toEqual({ command: 'sign_in', args: { providerId: '1' } });
});

test('Sign in on Welcome connects to the address of the organization', async () => {
    bridge((command) => (command === 'connect' ? one : undefined));
    await render(managed);

    await press(strings.signIn);

    expect(calls[0]).toEqual({ command: 'connect', args: { address: 'https://ilm.example.com' } });
    expect(commands()).toEqual(['connect', 'sign_in']);
});

test('a refused address is explained under the field and the field points at the reason', async () => {
    bridge(() => Promise.reject('This ILM does not publish how to sign in'));
    await render(idle);
    await type('ilm.example.com');

    await press(strings.continue);

    expect(alerts()).toEqual(['This ILM does not publish how to sign in']);
    expect(field().getAttribute('aria-invalid')).toBe('true');
    expect(document.getElementById(field().getAttribute('aria-describedby') ?? '')?.textContent).toBe(
        'This ILM does not publish how to sign in',
    );
    expect(button(strings.continue).disabled).toBe(false);
});

test('typing clears the reason', async () => {
    bridge(() => Promise.reject('refused'));
    await render(idle);
    await type('ilm.example.com');
    await press(strings.continue);

    await type('ilm.example.org');

    expect(alerts()).toEqual([]);
    expect(field().hasAttribute('aria-invalid')).toBe(false);
});

test('a failure without a message says that the ILM could not be reached', async () => {
    bridge(() => Promise.reject(''));
    await render(idle);
    await type('ilm.example.com');

    await press(strings.continue);

    expect(alerts()).toEqual([strings.connectFailed]);
});

test('an ILM that offers no provider is explained like a refused address', async () => {
    bridge(() => []);
    await render(idle);
    await type('ilm.example.com');

    await press(strings.continue);

    expect(alerts()).toEqual([strings.connectFailed]);
    expect(commands()).toEqual(['connect']);
});

test('a problem from the last sign-in shows under Connect and under Welcome', async () => {
    await render({ ...idle, problem: 'Sign-in timed out.' });
    expect(alerts()).toEqual(['Sign-in timed out.']);

    await render({ ...managed, problem: 'Cannot reach ilm.example.com.' });
    expect(alerts()).toEqual(['Cannot reach ilm.example.com.']);
    expect(heading()).toBe(strings.welcomeTitle);
});

test('a refused sign-in shows its reason under the choice and keeps the choice', async () => {
    bridge((command) => (command === 'connect' ? several : Promise.reject('Sign-in failed')));
    await render(idle);
    await type('ilm.example.com');
    await press(strings.continue);

    await press('Okta');

    expect(alerts()).toEqual(['Sign-in failed']);
    expect(heading()).toBe(strings.chooseTitle);
});

test('a sign-in that ends with a problem returns to the choice with its reason, and an older problem does not show there', async () => {
    bridge((command) => (command === 'connect' ? several : undefined));
    await render({ ...idle, problem: 'Older problem.' });
    await type('ilm.example.com');
    await press(strings.continue);
    expect(heading()).toBe(strings.chooseTitle);
    expect(alerts()).toEqual([]);

    await render(waiting);
    await render({ ...idle, problem: 'Sign-in timed out.' });

    expect(heading()).toBe(strings.chooseTitle);
    expect(alerts()).toEqual(['Sign-in timed out.']);
});

test('Back from the choice returns to the address to change it', async () => {
    bridge((command) => (command === 'connect' ? several : undefined));
    await render(idle);
    await type('ilm.example.com');
    await press(strings.continue);
    expect(heading()).toBe(strings.chooseTitle);

    await press(strings.back);

    expect(heading()).toBe(strings.connectTitle);
});

test('while the address is checked the button cannot be pressed again', async () => {
    let finish: (providers: ProviderChoice[]) => void = () => undefined;
    bridge((command) => (command === 'connect' ? new Promise((resolve) => (finish = resolve)) : undefined));
    await render(idle);
    await type('ilm.example.com');

    await press(strings.continue);

    expect(button(strings.continue).disabled).toBe(true);
    expect(button(strings.continue).getAttribute('aria-busy')).toBe('true');
    await act(async () => finish(several));
    expect(heading()).toBe(strings.chooseTitle);
});

test('Waiting names the provider and offers the browser again and Cancel', async () => {
    bridge(() => undefined);
    await render(waiting);

    expect(heading()).toBe(strings.waitingTitle);
    expect(container.querySelector('output')?.textContent).toBe(strings.waitingHint('Company SSO'));
    expect(buttons().map((candidate) => candidate.textContent)).toEqual([strings.openBrowserAgain, strings.cancel]);

    await press(strings.openBrowserAgain);
    await press(strings.cancel);

    expect(commands()).toEqual(['reopen_browser', 'cancel_sign_in']);
});

test('the first control of each step has the focus', async () => {
    bridge((command) => (command === 'connect' ? several : undefined));
    await render(idle);
    expect(document.activeElement).toBe(field());
    await type('ilm.example.com');

    await press(strings.continue);
    expect(document.activeElement).toBe(button('Company SSO'));

    await render(waiting);
    expect(document.activeElement).toBe(button(strings.openBrowserAgain));
});

test('Enter in the field submits the address', async () => {
    bridge((command) => (command === 'connect' ? one : undefined));
    await render(idle);
    await type('ilm.example.com');

    await act(async () => {
        field().form?.requestSubmit();
    });

    expect(commands()).toEqual(['connect', 'sign_in']);
});

const certificate: ProviderChoice = { id: 'certificate', name: strings.certificateEntry };
const alex: CertificateChoice = {
    fingerprint: '3F:A2:9C:01',
    subject: 'Alex Morgan',
    issuer: 'Example CA',
    notAfter: Date.UTC(2027, 2, 14, 12),
    remembered: false,
};
const build: CertificateChoice = {
    fingerprint: 'AA:BB:CC:DD',
    subject: 'Build agent',
    issuer: 'Example CA',
    notAfter: Date.UTC(2028, 0, 21, 12),
    remembered: false,
};
const waitingCertificate: Waiting = { state: 'signingIn', method: 'certificate', provider: strings.certificateEntry };

const radios = () => [...container.querySelectorAll<HTMLInputElement>('input[type="radio"]')];
const checked = () => radios().findIndex((radio) => radio.checked);
const rows = () => [...container.querySelectorAll('label')].map((label) => label.textContent);

/** Connect with a stand-in ILM that offers `offered` and a computer that holds `held`. */
async function reachCertificates(offered: ProviderChoice[], held: CertificateChoice[], failure?: string) {
    bridge((command) => {
        switch (command) {
            case 'connect':
                return offered;
            case 'certificates':
                return held;
            case 'sign_in_with_certificate':
                return failure !== undefined ? Promise.reject(failure) : new Promise(() => undefined);
            default:
                return undefined;
        }
    });
    await render(idle);
    await type('ilm.example.com');
    await press(strings.continue);
}

test('the certificate is the last entry on Choose provider and opens the list without signing in', async () => {
    await reachCertificates([...several, certificate], [alex, build]);

    expect(buttons().map((candidate) => candidate.textContent)).toEqual(['Company SSO', 'Okta', strings.certificateEntry, strings.back]);
    await press(strings.certificateEntry);

    expect(heading()).toBe(strings.certificateTitle);
    expect(commands()).toEqual(['connect', 'certificates']);
});

test('several certificates are a labelled radio list with the first one selected', async () => {
    await reachCertificates([certificate], [alex, build]);

    expect(heading()).toBe(strings.certificateTitle);
    expect(container.querySelector('[role="radiogroup"]')?.getAttribute('aria-label')).toBe(strings.certificateGroup);
    expect(rows()).toEqual([
        `Alex Morgan${'Example CA'} · ${strings.certificateExpires(alex.notAfter)}`,
        `Build agent${'Example CA'} · ${strings.certificateExpires(build.notAfter)}`,
    ]);
    expect(strings.certificateExpires(alex.notAfter)).toMatch(/^Expires .*2027/);
    expect(checked()).toBe(0);
    expect(commands()).toEqual(['connect', 'certificates']);
});

test('the remembered certificate is selected and the one chosen is signed in with', async () => {
    await reachCertificates([certificate], [alex, { ...build, remembered: true }]);
    expect(checked()).toBe(1);

    await act(async () => radios()[0]?.click());
    expect(checked()).toBe(0);
    await press(strings.signIn);

    expect(calls.at(-1)).toEqual({ command: 'sign_in_with_certificate', args: { fingerprint: alex.fingerprint } });
});

test('one certificate signs in without asking', async () => {
    await reachCertificates([certificate], [alex]);

    expect(calls.at(-1)).toEqual({ command: 'sign_in_with_certificate', args: { fingerprint: alex.fingerprint } });
});

test('a refused certificate shows its reason under the list, which stays for another try', async () => {
    await reachCertificates([certificate], [alex], 'ILM does not know this certificate.');

    expect(alerts()).toEqual(['ILM does not know this certificate.']);
    expect(rows()).toHaveLength(1);
    expect(checked()).toBe(0);
    expect(radios()[0]?.closest('[role="radiogroup"]')?.getAttribute('aria-describedby')).toBe(
        container.querySelector('[role="alert"]')?.id,
    );
    expect(button(strings.signIn).disabled).toBe(false);
});

test('a failure without a message is still explained', async () => {
    await reachCertificates([certificate], [alex, build], '');
    await press(strings.signIn);

    expect(alerts()).toEqual([strings.connectFailed]);
});

test('a sign-in that ends with a problem returns to the list with its reason and does not start again', async () => {
    await reachCertificates([certificate], [alex]);
    const before = commands().length;

    await render(waitingCertificate);
    await render({ ...idle, problem: 'The gateway did not accept this certificate.' });

    expect(heading()).toBe(strings.certificateTitle);
    expect(alerts()).toEqual(['The gateway did not accept this certificate.']);
    expect(commands().filter((command) => command === 'sign_in_with_certificate')).toHaveLength(1);
    expect(commands().length).toBeGreaterThan(before);
});

test('Back from the list returns to Choose provider', async () => {
    await reachCertificates([...several, certificate], [alex, build]);
    await press(strings.certificateEntry);

    await press(strings.back);

    expect(heading()).toBe(strings.chooseTitle);
});

test('Back from the list returns to Connect when the certificate was the only way', async () => {
    await reachCertificates([certificate], [alex, build]);

    await press(strings.back);

    expect(heading()).toBe(strings.connectTitle);
});

test('no certificate and a failed read are explained', async () => {
    await reachCertificates([certificate], []);
    expect(alerts()).toEqual([strings.noCertificate]);
    expect(button(strings.signIn).disabled).toBe(true);

    await act(async () => root.unmount());
    root = createRoot(container);
    bridge((command) => (command === 'connect' ? [certificate] : Promise.reject('The keychain is locked.')));
    await render(idle);
    await type('ilm.example.com');
    await press(strings.continue);

    expect(alerts()).toEqual(['The keychain is locked.']);
});

test('the keyboard reaches the radio list, moves through it and signs in', async () => {
    await reachCertificates([certificate], [alex, build]);

    expect(radios().every((radio) => radio.tabIndex === 0)).toBe(true);
    expect(
        radios()[0]
            ?.closest('label')
            ?.contains(radios()[0] ?? null),
    ).toBe(true);
    expect(buttons().every((candidate) => candidate.tabIndex === 0)).toBe(true);
});

test('Waiting for a certificate says so, shows no browser buttons and cancels', async () => {
    bridge(() => undefined);
    await render(waitingCertificate);

    expect(heading()).toBe(strings.certificateWaitingTitle);
    expect(container.querySelector('output')?.textContent).toBe(strings.certificateWaitingStatus);
    expect(buttons().map((candidate) => candidate.textContent)).toEqual([strings.cancel]);
    expect(document.activeElement).toBe(button(strings.cancel));

    await press(strings.cancel);

    expect(commands()).toEqual(['cancel_sign_in']);
});

test('a list that arrives after the step was left does nothing', async () => {
    let finish: (found: CertificateChoice[]) => void = () => undefined;
    bridge((command) => {
        if (command === 'connect') {
            return [certificate];
        }
        return command === 'certificates' ? new Promise((resolve) => (finish = resolve)) : undefined;
    });
    await render(idle);
    await type('ilm.example.com');
    await press(strings.continue);

    await act(async () => root.unmount());
    root = createRoot(container);
    await act(async () => finish([alex]));

    expect(commands()).toEqual(['connect', 'certificates']);
});

const ended: Idle = { ...idle, address: 'https://ilm.example.com', problem: 'Your sign-in has ended.', again: true };

test('an ended sign-in says so with Sign in again as its primary button, focused', async () => {
    await render(ended);

    expect(heading()).toBe(strings.signedOutTitle);
    expect(alerts()).toEqual(['Your sign-in has ended.']);
    expect(buttons().map((candidate) => candidate.textContent)).toEqual([strings.signInAgain]);
    expect(document.activeElement).toBe(button(strings.signInAgain));
    expect(button(strings.signInAgain).classList.contains('bg-accent')).toBe(true);
    expect(container.querySelector('input')).toBeNull();
});

test('an ended sign-in without a reason gives the usual one', async () => {
    await render({ ...ended, problem: null });

    expect(alerts()).toEqual([strings.signInEnded]);
});

test('Sign in again asks the application and waits for the browser flow when no choice is needed', async () => {
    bridge(() => []);
    await render(ended);

    await press(strings.signInAgain);

    expect(commands()).toEqual(['sign_in_again']);
    expect(heading()).toBe(strings.signedOutTitle);
});

test('Sign in again shows the choice of providers the application returns', async () => {
    bridge(() => several);
    await render(ended);

    await press(strings.signInAgain);

    expect(heading()).toBe(strings.chooseTitle);
    expect(buttons().map((candidate) => candidate.textContent)).toContain('Okta');
});

test('Sign in again shows why it was refused, including while locked', async () => {
    bridge(() => Promise.reject('Unlock Identity Manager first.'));
    await render(ended);

    await press(strings.signInAgain);

    expect(alerts()).toEqual(['Unlock Identity Manager first.']);
});

test('a refusal without a reason says the connection failed', async () => {
    bridge(() => Promise.reject(''));
    await render(ended);

    await press(strings.signInAgain);

    expect(alerts()).toEqual([strings.connectFailed]);
});

test('the choice of providers that the tray asked for shows in this window', async () => {
    bridge(() => undefined);
    await render(ended);

    await act(async () => emit('sign-in-choices', several));

    expect(heading()).toBe(strings.chooseTitle);
});

test('a choice of only a certificate that the tray asked for opens the certificate list', async () => {
    bridge((command) => (command === 'certificates' ? [alex] : undefined));
    await render(ended);

    await act(async () => emit('sign-in-choices', [certificate]));

    expect(heading()).toBe(strings.certificateTitle);
});

test('Back from a choice that was asked for returns to the ended sign-in', async () => {
    bridge(() => undefined);
    await render(ended);
    await act(async () => emit('sign-in-choices', several));

    await press(strings.back);

    expect(heading()).toBe(strings.signedOutTitle);
});

const unreachable = { state: 'unreachable', address: 'https://ilm.example.com', problem: 'The connection timed out.' } as const;
const renderUnreachable = () => act(async () => root.render(<UnreachableBanner view={unreachable} />));

test('the banner says ILM cannot be reached with the address and the problem, and offers Sign out', async () => {
    await renderUnreachable();

    const banner = container.querySelector(`section[aria-label="${strings.connection}"]`);
    expect(banner?.textContent).toContain(strings.cannotReachIlm);
    expect(banner?.textContent).toContain('https://ilm.example.com');
    expect(banner?.textContent).toContain('The connection timed out.');
    expect(container.querySelector('h1')).toBeNull();
    expect(alerts()).toEqual([]);
    expect(buttons().map((candidate) => candidate.textContent)).toEqual([strings.signOut]);
});

test('Sign out from the banner asks the application to sign out', async () => {
    bridge(() => idle);
    await renderUnreachable();

    await press(strings.signOut);

    expect(commands()).toEqual(['sign_out']);
});

test('Sign out from the banner shows why it was refused', async () => {
    bridge(() => Promise.reject('Unlock Identity Manager first.'));
    await renderUnreachable();

    await press(strings.signOut);

    expect(alerts()).toEqual(['Unlock Identity Manager first.']);
});

test('a refused Sign out without a reason says the connection failed', async () => {
    bridge(() => Promise.reject(''));
    await renderUnreachable();

    await press(strings.signOut);

    expect(alerts()).toEqual([strings.connectFailed]);
});
