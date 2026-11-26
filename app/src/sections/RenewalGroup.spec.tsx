import { clearMocks, mockIPC } from '@tauri-apps/api/mocks';
import { emit } from '@tauri-apps/api/event';
import { act } from 'react';
import { createRoot, type Root } from 'react-dom/client';
import { afterEach, beforeEach, expect, test, vi } from 'vitest';
import { ilmCertificate, inventory } from '../../playwright/ilm';
import { AppInfoContext } from '../app-info';
import type { FollowView, InventoryView, LocalCertificateView, RenewalView } from '../bridge';
import { strings } from '../strings';
import { Certificates } from './Certificates';

const now = new Date(2026, 5, 21, 10, 0, 0).getTime();
const day = 24 * 60 * 60 * 1000;

const mine: LocalCertificateView = {
    fingerprint: 'FP:one',
    name: 'Personal mTLS',
    subject: 'CN=Personal mTLS',
    issuer: 'CN=Demo Issuing CA',
    issuerName: 'Demo Issuing CA',
    serial: '5E:2B:9A',
    notBefore: now - 100 * day,
    notAfter: now + 17 * day,
    uses: [{ kind: 'clientAuth' }],
    alternativeNames: [],
    key: { kind: 'rsa', value: { bits: 2048 } },
    location: 'keychain',
    canSignIn: true,
    signInProblem: null,
    cardName: null,
};

const renewal = (over: Partial<RenewalView> = {}): RenewalView => ({
    renewable: true,
    automatic: true,
    locked: false,
    daysBefore: 30,
    from: null,
    newKey: true,
    replaced: false,
    replacedOn: null,
    replacedBy: null,
    canRevoke: false,
    waiting: false,
    revoking: null,
    ...over,
});

const successor: LocalCertificateView = {
    ...mine,
    fingerprint: 'FP:two',
    name: 'Renewed mTLS',
    notBefore: now - day,
    notAfter: now + 364 * day,
};

let container: HTMLElement;
let root: Root;
let current: InventoryView;
let calls: { command: string; args: unknown }[];
let follow: FollowView;
let renewAnswer: () => unknown;
let switchAnswer: () => unknown;

beforeEach(() => {
    (globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true;
    container = document.createElement('div');
    document.body.append(container);
    root = createRoot(container);
    calls = [];
    follow = { state: 'waiting', stage: 'pendingApproval' };
    renewAnswer = () => ({ certificate: 'new-cert', label: 'Personal mTLS' });
    switchAnswer = () => undefined;
    current = inventory({
        status: { state: 'fresh', checkedAt: now },
        checkedAt: now,
        checked: ['FP:one'],
        matches: { 'FP:one': ilmCertificate('Personal mTLS') },
        renewals: { 'FP:one': renewal() },
    });
    mockIPC(
        (command, args) => {
            calls.push({ command, args });
            switch (command) {
                case 'local_certificates':
                    return [mine, successor];
                case 'ilm_status':
                    return current;
                case 'renew_now':
                    return renewAnswer();
                case 'follow_request':
                    return follow;
                case 'set_renewal_switch':
                    return switchAnswer();
                case 'revoke_certificate':
                    return { certificate: 'cert-1', label: 'Personal mTLS' };
            }
        },
        { shouldMockEvents: true },
    );
});

afterEach(async () => {
    await act(async () => root.unmount());
    container.remove();
    clearMocks();
    vi.restoreAllMocks();
});

const render = () =>
    act(async () =>
        root.render(
            <AppInfoContext.Provider value={{ name: 'Identity Manager', version: '1', platform: 'macos' }}>
                <Certificates />
            </AppInfoContext.Provider>,
        ),
    );

const group = () =>
    [...container.querySelectorAll('section')].find((each) => each.querySelector('h3')?.textContent === strings.renewalGroupTitle);
const rows = () => [...(group()?.querySelectorAll('dt') ?? [])].map((dt) => [dt.textContent, dt.nextElementSibling?.textContent]);
const detail = () => container.querySelector('section#certificate-title, section[aria-labelledby="certificate-title"]') as HTMLElement;
const renewSwitch = () => container.querySelector<HTMLInputElement>('input[role="switch"]');
const renewButton = () => [...container.querySelectorAll('button')].find((each) => each.textContent === strings.renewNow);
const sent = (command: string) => calls.filter((call) => call.command === command);

test('a renewable certificate shows the group with the switch on, the timing, the key and the hint', async () => {
    await render();

    expect(rows()).toEqual([
        [strings.renewAutomatically, strings.switchOn],
        [strings.renewWhenRow, '30 days before expiry'],
        [strings.renewKeyRow, strings.renewNewKey],
    ]);
    expect(renewSwitch()?.checked).toBe(true);
    expect(renewSwitch()?.getAttribute('aria-label')).toBe(strings.renewAutomatically);
    expect(container.textContent).toContain(strings.renewalHint);
    expect(renewButton()).toBeDefined();
});

test('the switch shows off, the ILM window and the same key', async () => {
    current = {
        ...current,
        renewals: { 'FP:one': renewal({ automatic: false, from: now + 5 * day, newKey: false }) },
    };
    await render();

    expect(renewSwitch()?.checked).toBe(false);
    expect(rows()).toContainEqual([strings.renewWhenRow, strings.renewalFrom(strings.date(now + 5 * day))]);
    expect(rows()).toContainEqual([strings.renewKeyRow, strings.renewSameKey]);
});

test('a switch that policy fixes is disabled and says it is managed by the organization', async () => {
    current = { ...current, renewals: { 'FP:one': renewal({ automatic: false, locked: true }) } };
    await render();

    expect(renewSwitch()?.disabled).toBe(true);
    const note = document.getElementById(renewSwitch()?.getAttribute('aria-describedby') ?? '');
    expect(note?.textContent).toBe(strings.managedByOrganization);
});

test('turning the switch calls the command and shows the inventory it returns', async () => {
    const next = { ...current, renewals: { 'FP:one': renewal({ automatic: false }) } };
    switchAnswer = () => next;
    await render();

    await act(async () => renewSwitch()?.click());

    expect(sent('set_renewal_switch')[0]?.args).toEqual({ fingerprint: 'FP:one', on: false });
    expect(renewSwitch()?.checked).toBe(false);
});

test('a refused switch says why under the group', async () => {
    switchAnswer = () => Promise.reject('Automatic renewal is managed by your organization.');
    await render();

    await act(async () => renewSwitch()?.click());

    expect(container.querySelector('[role="alert"]')?.textContent).toBe('Automatic renewal is managed by your organization.');
    expect(renewSwitch()?.checked).toBe(true);
});

test('a switch refused without a reason says so in words', async () => {
    switchAnswer = () => Promise.reject('');
    await render();

    await act(async () => renewSwitch()?.click());

    expect(container.querySelector('[role="alert"]')?.textContent).toBe(strings.renewalSwitchFailed);
});

test('Renew now renews the certificate and says the renewal waits for approval', async () => {
    await render();

    await act(async () => renewButton()?.click());

    expect(sent('renew_now')[0]?.args).toEqual({ fingerprint: 'FP:one' });
    expect(sent('follow_request')[0]?.args).toEqual({ certificate: 'new-cert' });
    expect(detail().querySelector('output')?.textContent).toBe(strings.renewalWaitingForApproval);
    expect(renewButton()?.disabled).toBe(true);
});

test.each<[string, FollowView, string]>([
    ['issued', { state: 'waiting', stage: 'beingIssued' }, strings.renewalInProgress],
    ['unknown', { state: 'unknown' }, strings.renewalInProgress],
    ['installed', { state: 'installed', storage: 'keychain', validUntil: now }, strings.renewalDone],
    ['renewed beside', { state: 'renewed', validUntil: now }, strings.renewalDone],
])('a renewal that is %s says so in place', async (_name, view, said) => {
    follow = view;
    await render();

    await act(async () => renewButton()?.click());

    expect(detail().querySelector('output')?.textContent).toBe(said);
});

test.each<[string, FollowView, string]>([
    ['rejected', { state: 'ended', reason: 'rejected' }, strings.renewalRejected],
    ['not issued', { state: 'ended', reason: 'failed' }, strings.renewalNotIssued],
    ['not installed', { state: 'notInstalled', cause: 'installFailed' }, strings.renewalNotInstalled],
])('a renewal that is %s is said as an alert', async (_name, view, said) => {
    follow = view;
    await render();

    await act(async () => renewButton()?.click());

    expect(container.querySelector('[role="alert"]')?.textContent).toBe(said);
});

test.each([
    ['ILM does not allow this.', 'ILM does not allow this.'],
    ['', strings.renewalFailed],
])('a refused Renew now (%j) is shown under the group', async (reason, shown) => {
    renewAnswer = () => Promise.reject(reason);
    await render();

    await act(async () => renewButton()?.click());

    expect(container.querySelector('[role="alert"]')?.textContent).toBe(shown);
    expect(renewButton()?.disabled).toBe(false);
});

test('a refusal with ILM messages shows them', async () => {
    renewAnswer = () => Promise.reject({ kind: 'refused', messages: ['No.', 'Really no.'] });
    await render();

    await act(async () => renewButton()?.click());

    expect(container.querySelector('[role="alert"]')?.textContent).toBe('No. Really no.');
});

test('a refusal with problems is said in general words', async () => {
    renewAnswer = () => Promise.reject({ kind: 'problems', problems: [] });
    await render();

    await act(async () => renewButton()?.click());

    expect(container.querySelector('[role="alert"]')?.textContent).toBe(strings.renewalFailed);
});

test('a renewal that already waits disables Renew now and says so', async () => {
    current = { ...current, renewals: { 'FP:one': renewal({ waiting: true }) } };
    await render();

    expect(renewButton()?.disabled).toBe(true);
    expect(detail().querySelector('output')?.textContent).toBe(strings.renewalInProgress);
});

test.each([
    [now - 3 * day, strings.replacedByRenewalOn(strings.date(now - 3 * day))],
    [null, strings.replacedByRenewal],
])('a replaced certificate (%s) says so and has no switch and no Renew now', async (replacedOn, said) => {
    current = { ...current, renewals: { 'FP:one': renewal({ renewable: false, replaced: true, replacedOn }) } };
    await render();

    expect(rows()).toEqual([[strings.renewalGroupTitle, said]]);
    expect(renewSwitch()).toBeNull();
    expect(renewButton()).toBeUndefined();
});

test('a replaced certificate offers the certificate that replaced it and shows it when asked', async () => {
    current = { ...current, renewals: { 'FP:one': renewal({ renewable: false, replaced: true, replacedBy: 'FP:two' }) } };
    await render();
    const show = [...detail().querySelectorAll('button')].find((button) => button.textContent === strings.showRenewedCertificate);

    await act(async () => show?.click());

    expect(detail().querySelector('h2')?.textContent).toBe('Renewed mTLS');
});

test('a replaced certificate without a successor here offers nothing to show', async () => {
    current = { ...current, renewals: { 'FP:one': renewal({ renewable: false, replaced: true, replacedBy: null }) } };
    await render();

    expect(detail().textContent).not.toContain(strings.showRenewedCertificate);
});

test.each([
    ['no entry', {}],
    ['a revoke-only entry', { 'FP:one': renewal({ renewable: false, canRevoke: true }) }],
])('there is no group with %s', async (_name, renewals) => {
    current = { ...current, renewals };
    await render();

    expect(group()).toBeUndefined();
    expect(renewSwitch()).toBeNull();
});

test('Revoke… is shown only when ILM allows revoking the certificate', async () => {
    const revoke = () => [...container.querySelectorAll('button')].find((each) => each.textContent === strings.revoke);
    await render();
    expect(revoke()).toBeUndefined();

    current = { ...current, renewals: { 'FP:one': renewal({ canRevoke: true }) } };
    await act(async () => root.unmount());
    root = createRoot(container);
    await render();

    expect(revoke()).toBeDefined();
});

test('how a revocation ended stays shown when ILM no longer lets the person revoke and nothing waits', async () => {
    const button = (text: string) => [...container.querySelectorAll('button')].find((each) => each.textContent === text);
    current = { ...current, renewals: { 'FP:one': renewal({ canRevoke: true }) } };
    follow = { state: 'notRevoked' };
    await render();
    await act(async () => button(strings.revoke)?.click());
    await act(async () => button(strings.revokeConfirm)?.click());
    expect(detail().textContent).toContain(strings.revokeNotRevoked);

    current = { ...current, renewals: {} };
    await act(async () => emit('inventory-changed'));

    expect(detail().textContent).toContain(strings.revokeNotRevoked);
    expect(button(strings.revoke)).toBeUndefined();
});
