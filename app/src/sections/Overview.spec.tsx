import { emit } from '@tauri-apps/api/event';
import { clearMocks, mockIPC } from '@tauri-apps/api/mocks';
import { act } from 'react';
import { createRoot, type Root } from 'react-dom/client';
import { afterEach, beforeEach, expect, test } from 'vitest';
import { inventory as checkedInventory } from '../../playwright/ilm';
import { AppInfoContext } from '../app-info';
import type { AttentionItemView, InventoryView, LocalCertificateView, Platform, SummaryView } from '../bridge';
import { IlmWaitingContext } from '../ilm-waiting';
import { NavigationContext } from '../navigation';
import { strings } from '../strings';
import { Overview } from './Overview';

const computedAt = new Date(2026, 10, 20, 10, 38).getTime();
const day = 24 * 60 * 60 * 1000;

const local = (name: string, over: Partial<LocalCertificateView> = {}): LocalCertificateView => ({
    fingerprint: `FP:${name}`,
    name,
    subject: `CN=${name}`,
    issuer: 'CN=Demo Issuing CA',
    issuerName: 'Demo Issuing CA',
    serial: '5E:2B:9A',
    notBefore: computedAt - 100 * day,
    notAfter: computedAt + 212 * day,
    uses: [],
    alternativeNames: [],
    key: { kind: 'rsa', value: { bits: 2048 } },
    location: 'keychain',
    canSignIn: true,
    signInProblem: null,
    cardName: null,
    ...over,
});

const revoked: AttentionItemView = { kind: 'revoked', fingerprint: 'FP:Build server', name: 'Build server' };
const expired: AttentionItemView = { kind: 'expired', fingerprint: 'FP:Smart card', name: 'Smart card login', on: computedAt - 6 * day };
const expiring: AttentionItemView = {
    kind: 'expiring',
    fingerprint: 'FP:vpn',
    name: 'vpn.example.com',
    days: 13,
    on: computedAt + 13 * day,
    renewable: false,
};
const tomorrow: AttentionItemView = {
    kind: 'expiring',
    fingerprint: 'FP:soon',
    name: 'Soon',
    days: 1,
    on: computedAt + day,
    renewable: false,
};
const approval: AttentionItemView = { kind: 'waiting', label: 'User mTLS', state: 'pendingApproval' };
const issuing: AttentionItemView = { kind: 'waiting', label: 'Code signing', state: 'beingIssued' };
const unmatched = (count: number): AttentionItemView => ({ kind: 'notInIlm', count });

const stand = (attention: AttentionItemView[], over: Partial<SummaryView> = {}): SummaryView => ({
    computedAt,
    checkedAt: computedAt,
    listed: true,
    counts: { valid: 3, expiring: 2, expired: 2, notInIlm: 3 },
    attention,
    months: [0, 2, 0, 1, 0, 1, 0, 1, 0, 2, 0, 1],
    ...over,
});

const wifi = local('wifi-corp');
const vpn = local('vpn-client');
const lab = local('Lab device');
const everything = [wifi, vpn, lab];
const fresh = (over: Partial<InventoryView> = {}) =>
    checkedInventory({ status: { state: 'fresh', checkedAt: computedAt }, checkedAt: computedAt, ...over });

let container: HTMLElement;
let root: Root;
let summary: SummaryView | null | 'refused';
let certificates: LocalCertificateView[] | 'refused';
let current: InventoryView | null;
let calls: { command: string; args: unknown }[];
let shown: string[];
let choices: unknown;
let added: unknown;
/** While set, each read of the certificates waits here until it is answered. */
let renewing: () => unknown;
let reads: ((items: LocalCertificateView[]) => void)[] | null;

beforeEach(() => {
    (globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true;
    container = document.createElement('div');
    document.body.append(container);
    root = createRoot(container);
    summary = stand([revoked, expired, expiring, unmatched(3)]);
    certificates = everything;
    current = fresh({ checked: everything.map((certificate) => certificate.fingerprint) });
    calls = [];
    shown = [];
    choices = { groups: null, raProfiles: null };
    added = [];
    reads = null;
    renewing = () => ({ certificate: 'new', label: 'x' });
    mockIPC(
        (command, args) => {
            calls.push({ command, args });
            switch (command) {
                case 'overview':
                    return summary === 'refused' ? Promise.reject('locked') : summary;
                case 'local_certificates':
                    if (reads) {
                        return new Promise((resolve) => reads?.push(resolve));
                    }
                    return certificates === 'refused' ? Promise.reject('unreadable') : certificates;
                case 'ilm_status':
                    return current;
                case 'sync_now':
                    return current;
                case 'add_to_ilm_choices':
                    return choices;
                case 'add_to_ilm':
                    return added;
                case 'renew_now':
                    return renewing();
                case 'follow_request':
                    return { state: 'waiting', stage: 'pendingApproval' };
            }
        },
        { shouldMockEvents: true },
    );
});

afterEach(async () => {
    await act(async () => root.unmount());
    container.remove();
    clearMocks();
});

const render = (platform: Platform = 'macos', waiting = false) =>
    act(async () =>
        root.render(
            <AppInfoContext.Provider value={{ name: 'Identity Manager', version: '1', platform }}>
                <IlmWaitingContext.Provider value={waiting}>
                    <NavigationContext.Provider value={{ showing: null, showCertificate: (fingerprint) => shown.push(fingerprint) }}>
                        <Overview />
                    </NavigationContext.Provider>
                </IlmWaitingContext.Provider>
            </AppInfoContext.Provider>,
        ),
    );

const text = () => container.textContent ?? '';
const tiles = () => [...container.querySelectorAll('ul[aria-label] > li')].map((tile) => tile.textContent);
const rows = () => [...(container.querySelector('section')?.querySelectorAll('ul > li') ?? [])].map((row) => row.textContent);
const button = (name: string) =>
    [...container.querySelectorAll('button')].find(
        (candidate) => candidate.getAttribute('aria-label') === name || candidate.textContent === name,
    );
const bars = () => [...container.querySelectorAll('ol[aria-label] > li')];
const month = (index: number) => strings.month(new Date(2026, 10 + index, 1).getTime());

test('has the name of the section and the check time with a Sync now button', async () => {
    await render();

    expect(container.querySelector('h1')?.textContent).toBe('Overview');
    expect(text()).toContain(strings.checkedWithIlm(computedAt));
    await act(async () => button(strings.syncNow)?.click());
    expect(calls.map((call) => call.command)).toContain('sync_now');
});

test('says that ILM is being checked, and that it cannot be reached', async () => {
    current = fresh({ checking: true });
    await render();
    expect(text()).toContain(strings.checkingIlm);

    current = fresh({ status: { state: 'offline', since: computedAt, reason: 'no route', unreachable: true } });
    await act(async () => emit('inventory-changed'));
    expect(text()).toContain(strings.cannotReachIlmSince(computedAt));
});

test('a failed Sync now is said in words', async () => {
    mockIPC(
        (command) => {
            if (command === 'sync_now') {
                return Promise.reject('');
            }
            return command === 'overview' ? summary : command === 'ilm_status' ? current : [];
        },
        { shouldMockEvents: true },
    );
    await render();

    await act(async () => button(strings.syncNow)?.click());

    expect(container.querySelector('[role="alert"]')?.textContent).toBe(strings.syncFailed);
});

test('shows nothing but the header before the summary is read, and when it is refused', async () => {
    summary = 'refused';
    await render();

    expect(container.querySelector('h1')).not.toBeNull();
    expect(container.querySelector('ul')).toBeNull();
    expect(container.querySelector('h2')).toBeNull();
});

test('the counts are a list named by what it counts, with a muted tile for a zero', async () => {
    summary = stand([revoked], { counts: { valid: 7, expiring: 0, expired: 1, notInIlm: 0 } });
    await render();

    expect(container.querySelector('ul[aria-label]')?.getAttribute('aria-label')).toBe(strings.countsLabel);
    expect(tiles()).toEqual(['7Valid', '0Expiring soon', '1Expired', '0Not in ILM']);
    const muted = [...container.querySelectorAll('ul[aria-label] > li')].map((tile) => tile.querySelector('.text-tertiary') !== null);
    expect(muted).toEqual([false, true, false, true]);
});

test('there is no Not in ILM tile when certificates are not listed', async () => {
    summary = stand([], { counts: { valid: 3, expiring: 0, expired: 0, notInIlm: null }, listed: false });
    await render();

    expect(tiles()).toEqual(['3Valid', '0Expiring soon', '0Expired']);
});

test('each item that needs attention says what is the matter and has Show, named by its certificate', async () => {
    await render();

    expect(rows()).toEqual([
        `Build server${strings.revokedInIlm}Show`,
        `Smart card login${strings.expiredOnDate(strings.date(expired.on))}Show`,
        `vpn.example.com${strings.expiresOnDate(strings.date(expiring.on), 13)}Show`,
        `${strings.notInIlmCount(3, 'macos')}wifi-corp, vpn-client and Lab deviceAdd to ILM`,
    ]);
    const names = [...(container.querySelector('section')?.querySelectorAll('ul > li button') ?? [])].map((candidate) =>
        candidate.getAttribute('aria-label'),
    );
    expect(names).toEqual(['Show Build server', 'Show Smart card login', 'Show vpn.example.com', strings.addToIlm]);
});

const sections = () => [...container.querySelectorAll('section')];
const headings = () => sections().map((section) => section.querySelector('h2')?.textContent);

test('requests in progress are their own section between the counts and what needs attention, with no button', async () => {
    summary = stand([approval, issuing, revoked]);
    await render();

    expect(headings().slice(0, 2)).toEqual([strings.requestsInProgress, strings.needsAttention]);
    const progress = sections()[0];
    expect([...(progress?.querySelectorAll('ul > li') ?? [])].map((row) => row.textContent)).toEqual([
        `User mTLS${strings.waitingForApproval}`,
        `Code signing${strings.beingIssued}`,
    ]);
    expect(progress?.querySelector('button')).toBeNull();
    expect(sections()[1]?.textContent).not.toContain('User mTLS');
    expect(sections()[1]?.textContent).toContain('Build server');
});

test('without requests in progress there is no such section', async () => {
    await render();

    expect(headings()).not.toContain(strings.requestsInProgress);
});

test('requests in progress alone leave nothing that needs attention', async () => {
    summary = stand([issuing], { counts: { valid: 3, expiring: 0, expired: 0, notInIlm: 0 } });
    await render();

    expect(headings().slice(0, 2)).toEqual([strings.requestsInProgress, strings.needsAttention]);
    expect(sections()[1]?.querySelector('p')?.textContent).toBe(strings.nothingNeedsAttention);
});

test('Show opens the certificate in Certificates', async () => {
    await render();

    await act(async () => button('Show vpn.example.com')?.click());

    expect(shown).toEqual(['FP:vpn']);
});

test('a certificate that expires tomorrow says tomorrow, a single one not in ILM says certificate', async () => {
    summary = stand([tomorrow, unmatched(1)]);
    certificates = [wifi];
    current = fresh({ checked: [wifi.fingerprint] });
    await render('windows');

    expect(rows()[0]).toContain('Expires tomorrow, ');
    expect(rows()[1]).toContain('1 certificate on this PC is not in ILM');
});

test('says that nothing needs attention', async () => {
    summary = stand([], { counts: { valid: 7, expiring: 0, expired: 1, notInIlm: 0 } });
    await render();

    expect(container.querySelector('section p')?.textContent).toBe(strings.nothingNeedsAttention);
    expect(container.querySelector('section ul')).toBeNull();
});

test('Add to ILM opens the dialog with every certificate ILM does not know, checked', async () => {
    await render();

    await act(async () => button(strings.addToIlm)?.click());

    expect(container.querySelector('dialog h2')?.textContent).toBe(strings.addTitle(3));
    const boxes = [...container.querySelectorAll<HTMLInputElement>('dialog input[type="checkbox"]')];
    expect(boxes.map((box) => box.checked)).toEqual([true, true, true]);
    expect(button(strings.addCount(3))).toBeDefined();
});

test('an older read of the certificates that ends after a newer one is ignored', async () => {
    reads = [];
    await render();
    await act(async () => emit('inventory-changed'));
    expect(reads).toHaveLength(2);

    await act(async () => reads?.[1]?.([wifi]));
    await act(async () => reads?.[0]?.(everything));
    await act(async () => button(strings.addToIlm)?.click());

    expect(container.querySelector('dialog h2')?.textContent).toBe(strings.addTitle(1));
});

test('the dialog keeps its certificates after the check has made ILM know them', async () => {
    added = everything.map((certificate) => ({ fingerprint: certificate.fingerprint, outcome: 'added', messages: [] }));
    await render();
    await act(async () => button(strings.addToIlm)?.click());
    await act(async () => button(strings.addCount(3))?.click());

    current = fresh({ checked: everything.map((c) => c.fingerprint), matches: {} });
    summary = stand([], { counts: { valid: 3, expiring: 0, expired: 0, notInIlm: 0 } });
    certificates = [];
    await act(async () => emit('inventory-changed'));

    expect(container.querySelector('dialog h2')?.textContent).toBe(strings.addTitle(3));
    expect(container.querySelector('dialog')?.textContent).toContain('wifi-corp');
    await act(async () => button(strings.close)?.click());
    expect(container.querySelector('dialog')).toBeNull();
});

test.each([
    [
        'ILM cannot be reached',
        () =>
            fresh({
                checked: ['FP:wifi-corp'],
                status: { state: 'offline', since: computedAt, reason: 'x', unreachable: true },
            }),
        false,
    ],
    ['the saved sign-in waits for ILM', () => fresh({ checked: ['FP:wifi-corp'] }), true],
])('there is no Add to ILM when %s, but the item is still said', async (_, status, waiting) => {
    current = status();
    await render('macos', waiting);

    expect(text()).toContain(strings.notInIlmCount(3, 'macos'));
    expect(button(strings.addToIlm)).toBeUndefined();
});

test('there is no Add to ILM before the local certificates are known', async () => {
    certificates = 'refused';
    await render();

    expect(rows().at(-1)).toBe(strings.notInIlmCount(3, 'macos'));
    expect(button(strings.addToIlm)).toBeUndefined();
});

test('the chart has twelve bars with their count and month, the current month first', async () => {
    await render();

    expect(container.querySelector('ol[aria-label]')?.getAttribute('aria-label')).toBe(strings.expiryChartLabel);
    expect(bars()).toHaveLength(12);
    expect(bars().map((bar) => bar.textContent)).toEqual(
        [0, 2, 0, 1, 0, 1, 0, 1, 0, 2, 0, 1].map((count, index) => `${count}${month(index)}`),
    );
    expect(bars()[0]?.querySelector('.font-semibold')?.textContent).toBe(month(0));
    const heights = bars().map((bar) => (bar.querySelector('[aria-hidden]') as HTMLElement).style.height);
    expect(heights).toEqual(['2px', '56px', '2px', '28px', '2px', '28px', '2px', '28px', '2px', '56px', '2px', '28px']);
});

test('a small share still has a bar that can be seen', async () => {
    summary = stand([], { months: [0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 100] });
    await render();

    expect(bars().map((bar) => (bar.querySelector('[aria-hidden]') as HTMLElement).style.height)[1]).toBe('4px');
});

test('a chart with nothing in it still draws the stubs', async () => {
    summary = stand([], { months: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] });
    await render();

    expect(bars().map((bar) => (bar.querySelector('[aria-hidden]') as HTMLElement).style.height)).toEqual(Array(12).fill('2px'));
});

test('the months start from the one the summary was computed in, across the year', async () => {
    summary = stand([], { computedAt: new Date(2026, 11, 31, 23, 0).getTime() });
    await render();

    expect(bars()[0]?.textContent).toContain(strings.month(new Date(2026, 11, 1).getTime()));
    expect(bars()[1]?.textContent).toContain(strings.month(new Date(2027, 0, 1).getTime()));
});

test('the certificates expiring within the warning days are listed under the chart', async () => {
    await render();

    const list = container.querySelector('ul[aria-label="Certificates expiring soon"]');
    expect(list?.textContent).toBe(`vpn.example.com ${strings.expiresOn(strings.date(expiring.on), 13)}`);
});

test('no list is drawn under the chart when none is expiring', async () => {
    summary = stand([revoked]);
    await render();

    expect(container.querySelector('ul[aria-label="Certificates expiring soon"]')).toBeNull();
});

test.each([
    ['macos', 'Mac'],
    ['windows', 'PC'],
] as const)('with no certificates with a private key it says so for the %s and draws no chart', async (platform, word) => {
    summary = stand([], { counts: { valid: 0, expiring: 0, expired: 0, notInIlm: 0 }, months: Array(12).fill(0) as SummaryView['months'] });
    await render(platform);

    expect(text()).toContain(`No certificates with a private key on this ${word}.`);
    expect(tiles()).toEqual(['0Valid', '0Expiring soon', '0Expired', '0Not in ILM']);
    expect(container.querySelector('ol')).toBeNull();
    expect(container.querySelector('h2')).toBeNull();
});

test('is read again when the inventory changes', async () => {
    await render();
    summary = stand([], { counts: { valid: 9, expiring: 0, expired: 0, notInIlm: 0 } });

    await act(async () => emit('inventory-changed'));

    expect(tiles()[0]).toBe('9Valid');
    expect(text()).toContain(strings.nothingNeedsAttention);
});

const renewable: AttentionItemView = { ...expiring, renewable: true };

test('an expiring certificate that can be renewed has Renew, named by it, next to Show', async () => {
    summary = stand([renewable, expiring]);
    await render();

    const names = [...(container.querySelector('section')?.querySelectorAll('ul > li button') ?? [])].map((each) =>
        each.getAttribute('aria-label'),
    );
    expect(names).toEqual(['Show vpn.example.com', 'Renew vpn.example.com', 'Show vpn.example.com']);
    expect(button('Renew vpn.example.com')?.textContent).toBe(strings.renew);
});

test('Renew renews that certificate and says it waits for approval, without another Renew', async () => {
    summary = stand([renewable]);
    await render();

    await act(async () => button('Renew vpn.example.com')?.click());

    expect(calls.find((call) => call.command === 'renew_now')?.args).toEqual({ fingerprint: 'FP:vpn' });
    expect(container.querySelector('section ul output')?.textContent).toBe(strings.renewalWaitingForApproval);
    expect(button('Renew vpn.example.com')).toBeUndefined();
});

test('a refused Renew says why and keeps the button', async () => {
    summary = stand([renewable]);
    renewing = () => Promise.reject('ILM does not allow this.');
    await render();

    await act(async () => button('Renew vpn.example.com')?.click());

    expect(container.querySelector('[role="alert"]')?.textContent).toBe('ILM does not allow this.');
    expect(button('Renew vpn.example.com')).toBeDefined();
});

test('while Renew is sent the button says Renewing and is disabled', async () => {
    summary = stand([renewable]);
    renewing = () => new Promise(() => undefined);
    await render();

    await act(async () => button('Renew vpn.example.com')?.click());

    const busy = button('Renew vpn.example.com') as HTMLButtonElement;
    expect(busy.textContent).toBe(strings.renewing);
    expect(busy.disabled).toBe(true);
});
