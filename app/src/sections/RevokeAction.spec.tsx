import { clearMocks, mockIPC } from '@tauri-apps/api/mocks';
import { act } from 'react';
import { createRoot, type Root } from 'react-dom/client';
import { afterEach, beforeEach, expect, test, vi } from 'vitest';
import type { FollowView, KeyLocation, LocalCertificateView, RenewalView, RevokingStage } from '../bridge';
import { strings } from '../strings';
import { RevokeAction } from './RevokeAction';

const mine: LocalCertificateView = {
    fingerprint: 'FP:one',
    name: 'Personal mTLS',
    subject: 'CN=Personal mTLS',
    issuer: 'CN=Demo Issuing CA',
    issuerName: 'Demo Issuing CA',
    serial: '5E:2B:9A',
    notBefore: 0,
    notAfter: 1,
    uses: [],
    alternativeNames: [],
    key: { kind: 'rsa', value: { bits: 2048 } },
    location: 'keychain',
    canSignIn: true,
    signInProblem: null,
    cardName: null,
};

const renewal = (revoking: RevokingStage | null): RenewalView => ({
    renewable: false,
    automatic: true,
    locked: false,
    daysBefore: 30,
    from: null,
    newKey: false,
    replaced: false,
    replacedOn: null,
    replacedBy: null,
    canRevoke: true,
    waiting: false,
    revoking,
});

let container: HTMLElement;
let root: Root;
let calls: { command: string; args: unknown }[];
let follows: FollowView[];
let revokeAnswer: () => unknown;

beforeEach(() => {
    (globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true;
    vi.useFakeTimers({ toFake: ['setTimeout', 'clearTimeout'] });
    container = document.createElement('div');
    document.body.append(container);
    root = createRoot(container);
    calls = [];
    follows = [{ state: 'revoking', stage: 'beingRevoked' }];
    revokeAnswer = () => ({ certificate: 'revocation', label: 'Personal mTLS' });
    mockIPC((command, args) => {
        calls.push({ command, args });
        if (command === 'revoke_certificate') {
            return revokeAnswer();
        }
        if (command === 'follow_request') {
            return follows.length > 1 ? follows.shift() : follows[0];
        }
    });
});

afterEach(async () => {
    await act(async () => root.unmount());
    container.remove();
    clearMocks();
    vi.useRealTimers();
});

const render = (location: KeyLocation = 'keychain', system: 'macos' | 'windows' = 'macos', revoking: RevokingStage | null = null) =>
    act(async () => root.render(<RevokeAction certificate={{ ...mine, location }} system={system} renewal={renewal(revoking)} />));
const buttons = () => [...container.querySelectorAll('button')];
const named = (text: string) => buttons().find((each) => each.textContent === text) as HTMLButtonElement;
const dialog = () => container.querySelector('dialog') as HTMLDialogElement;
const select = () => container.querySelector('select') as HTMLSelectElement;
const checkbox = () => container.querySelector<HTMLInputElement>('input[type="checkbox"]');
const open = () => act(async () => named(strings.revoke).click());
const confirm = () => act(async () => named(strings.revokeConfirm).click());
const sent = (command: string) => calls.filter((call) => call.command === command);
const status = () => container.querySelector('output')?.textContent;

test('the button opens the question with the name, the message and the reasons in order', async () => {
    await render();
    expect(dialog()).toBeNull();

    await open();

    expect(dialog().querySelector('h2')?.textContent).toBe('Revoke Personal mTLS?');
    expect(dialog().textContent).toContain('It stops working everywhere within minutes. This cannot be undone.');
    expect([...select().options].map((each) => each.textContent)).toEqual([
        'No longer needed',
        'Replaced',
        'Key compromised',
        'Affiliation changed',
        'Privilege withdrawn',
        'Unspecified',
    ]);
    expect(select().value).toBe('cessationOfOperation');
    expect(container.querySelector(`label[for="${select().id}"]`)?.textContent).toBe('Reason');
});

test('the confirming button is destructive and Cancel closes the question', async () => {
    await render();
    await open();

    expect(named(strings.revokeConfirm).className).toContain('bg-bad');
    await act(async () => named(strings.cancel).click());

    expect(dialog()).toBeNull();
    expect(sent('revoke_certificate')).toHaveLength(0);
});

test.each<[KeyLocation, 'macos' | 'windows', string | null]>([
    ['keychain', 'macos', 'Delete it and its private key from this Mac'],
    ['software', 'windows', 'Delete it and its private key from this PC'],
    ['tpm', 'windows', 'Delete it and its private key from this PC'],
    ['smartCard', 'macos', null],
    ['smartCard', 'windows', 'Remove it from this PC'],
    ['secureEnclave', 'macos', null],
    ['unknown', 'windows', null],
])('a %s certificate on %s offers the checkbox %s', async (location, system, label) => {
    await render(location, system);
    await open();

    expect(checkbox()?.parentElement?.textContent ?? null).toBe(label);
    expect(checkbox()?.checked ?? false).toBe(false);
});

test('Revoke sends the chosen reason and keeps the certificate by default', async () => {
    await render();
    await open();
    await act(async () => {
        select().value = 'keyCompromise';
        select().dispatchEvent(new Event('change', { bubbles: true }));
    });
    await confirm();

    expect(sent('revoke_certificate')[0]?.args).toEqual({ fingerprint: 'FP:one', reason: 'keyCompromise', remove: false });
});

test('with the checkbox ticked the certificate is removed too', async () => {
    await render();
    await open();
    await act(async () => checkbox()?.click());
    await confirm();

    expect(sent('revoke_certificate')[0]?.args).toEqual({ fingerprint: 'FP:one', reason: 'cessationOfOperation', remove: true });
});

test('a certificate with no checkbox is never removed', async () => {
    await render('secureEnclave');
    await open();
    await confirm();

    expect(sent('revoke_certificate')[0]?.args).toMatchObject({ remove: false });
});

test('while it is sent the question is busy and cannot be cancelled', async () => {
    let accept: (value: unknown) => void = () => undefined;
    revokeAnswer = () => new Promise((resolve) => (accept = resolve));
    await render();
    await open();
    await confirm();

    expect(named(strings.revokeConfirm).disabled).toBe(true);
    expect(named(strings.cancel).disabled).toBe(true);

    await act(async () => accept({ certificate: 'revocation', label: 'x' }));
    expect(dialog()).toBeNull();
});

test('a refusal is shown in the question, which stays open and can be tried again', async () => {
    revokeAnswer = () => Promise.reject({ kind: 'refused', messages: ['Not allowed.', 'Ask an administrator.'] });
    await render();
    await open();
    await confirm();

    expect(dialog().querySelector('[role="alert"]')?.textContent).toBe('Not allowed. Ask an administrator.');
    expect(named(strings.revokeConfirm).disabled).toBe(false);
    expect(named(strings.cancel).disabled).toBe(false);

    revokeAnswer = () => ({ certificate: 'revocation', label: 'x' });
    await confirm();

    expect(dialog()).toBeNull();
    expect(sent('revoke_certificate')).toHaveLength(2);
});

test('an error without words says that it could not be revoked', async () => {
    revokeAnswer = () => Promise.reject({ kind: 'refused', messages: [] });
    await render();
    await open();
    await confirm();

    expect(dialog().querySelector('[role="alert"]')?.textContent).toBe(strings.revokeFailed);
});

test('the revocation is followed: Revoking… then Revoked., and the button stays off', async () => {
    follows = [{ state: 'revoking', stage: 'beingRevoked' }, { state: 'revoked' }];
    await render();
    await open();
    await confirm();

    expect(dialog()).toBeNull();
    expect(status()).toBe(strings.revoking);
    expect(named(strings.revoke).disabled).toBe(true);

    await act(async () => vi.advanceTimersByTimeAsync(2000));

    expect(status()).toBe(strings.revokeDone);
    expect(named(strings.revoke).disabled).toBe(true);
    expect(sent('stop_following_request')).toHaveLength(1);
});

test('a revocation that removed the certificate says so', async () => {
    follows = [{ state: 'revoked' }];
    await render();
    await open();
    await act(async () => checkbox()?.click());
    await confirm();
    await act(async () => vi.advanceTimersByTimeAsync(0));

    expect(status()).toBe(strings.revokeDoneRemoved);
});

test('an answer that is not known yet says Revoking…', async () => {
    follows = [{ state: 'unknown' }];
    await render();
    await open();
    await confirm();

    expect(status()).toBe(strings.revoking);
});

test('ILM not revoking it is an alert and the button is on again', async () => {
    follows = [{ state: 'notRevoked' }];
    await render();
    await open();
    await confirm();

    expect(container.querySelector('[role="alert"]')?.textContent).toBe(strings.revokeNotRevoked);
    expect(named(strings.revoke).disabled).toBe(false);
});

test('a retry after ILM did not revoke it drops the old outcome, so a revocation left waiting is told', async () => {
    follows = [{ state: 'notRevoked' }];
    await render();
    await open();
    await confirm();
    expect(container.querySelector('[role="alert"]')?.textContent).toBe(strings.revokeNotRevoked);

    revokeAnswer = () => Promise.reject({ kind: 'message', message: 'ILM cannot be reached.' });
    await open();
    await confirm();
    await act(async () => root.render(<RevokeAction certificate={mine} system="macos" renewal={renewal('beingRevoked')} />));

    expect(status()).toBe(strings.revoking);
    expect(named(strings.revoke).disabled).toBe(true);
});

test('following gives up after thirty answers and clears the status', async () => {
    follows = [{ state: 'revoking', stage: 'beingRevoked' }];
    await render();
    await open();
    await confirm();

    await act(async () => vi.advanceTimersByTimeAsync(2000 * 40));

    expect(sent('follow_request')).toHaveLength(30);
    expect(sent('stop_following_request')).toHaveLength(1);
    expect(status()).toBeUndefined();
});

test('leaving the screen stops following', async () => {
    await render();
    await open();
    await confirm();

    await act(async () => root.unmount());
    await act(async () => vi.advanceTimersByTimeAsync(10000));

    expect(sent('follow_request')).toHaveLength(1);
    expect(sent('stop_following_request')).toHaveLength(1);
    root = createRoot(container);
});

test('the follow of a revocation that waits for approval says so', async () => {
    follows = [
        { state: 'revoking', stage: 'pendingApproval' },
        { state: 'revoking', stage: 'beingRevoked' },
    ];
    await render();
    await open();
    await confirm();
    await act(async () => vi.advanceTimersByTimeAsync(0));

    expect(status()).toBe(strings.revokePendingApproval);

    await act(async () => vi.advanceTimersByTimeAsync(2000));

    expect(status()).toBe(strings.revoking);
});

test.each<[RevokingStage, string]>([
    ['pendingApproval', strings.revokePendingApproval],
    ['beingRevoked', strings.revoking],
])('a revocation the view shows as %s is told with no follow, as after a reload', async (stage, text) => {
    await render('keychain', 'macos', stage);

    expect(status()).toBe(text);
    expect(named(strings.revoke).disabled).toBe(true);
    expect(sent('follow_request')).toHaveLength(0);
});

test('with no revocation in the view nothing is told and the button is on', async () => {
    await render();

    expect(status()).toBeUndefined();
    expect(named(strings.revoke).disabled).toBe(false);
});
