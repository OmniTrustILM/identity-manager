import { clearMocks, mockIPC } from '@tauri-apps/api/mocks';
import { act } from 'react';
import { createRoot, type Root } from 'react-dom/client';
import { afterEach, beforeEach, expect, test } from 'vitest';
import type { ProviderChoice, SessionView } from '../bridge';
import { strings } from '../strings';
import { SignIn } from './SignIn';

type Waiting = Extract<SessionView, { state: 'signingIn' }>;
type Idle = Extract<SessionView, { state: 'signedOut' }>;

const idle: Idle = { state: 'signedOut', address: null, locked: false, problem: null };
const managed: Idle = { ...idle, address: 'https://ilm.example.com', locked: true };
const waiting: Waiting = { state: 'signingIn', provider: 'Company SSO' };
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
    mockIPC((command, args) => {
        calls.push({ command, args });
        return handler(command, args);
    });
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
    expect(buttons().map((candidate) => candidate.textContent)).toEqual(['Company SSO', 'Okta']);
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
    expect(container.querySelector('[role="status"]')?.textContent).toBe(strings.waitingHint('Company SSO'));
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
