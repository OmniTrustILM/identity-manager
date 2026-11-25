import { emit } from '@tauri-apps/api/event';
import { clearMocks, mockIPC } from '@tauri-apps/api/mocks';
import { act } from 'react';
import { createRoot, type Root } from 'react-dom/client';
import { afterEach, beforeEach, expect, test, vi } from 'vitest';
import { AppInfoContext } from '../../app-info';
import type { AppInfo, AttentionItemView, SessionView, SummaryView } from '../../bridge';
import { strings } from '../../strings';
import { TraySummary } from './TraySummary';

const info: AppInfo = {
    name: 'Identity Manager',
    version: '0.1.0',
    platform: 'macos',
};

const signedIn: SessionView = {
    state: 'signedIn',
    address: 'https://develop-02.example.com',
    person: { name: 'Alex Morgan', username: 'alex.morgan' },
    allowedListings: [],
    certificate: null,
    unreachable: false,
};
const signedOut: SessionView = { state: 'signedOut', address: null, locked: false, problem: null, again: false };

let container: HTMLElement;
let session: SessionView;
let refusal: string | undefined;
let summary: SummaryView | null;
let overviews: number;
let opened: unknown[];
let root: Root;
let calls: string[];
let reports: unknown[];

beforeEach(async () => {
    (globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true;
    container = document.createElement('div');
    document.body.append(container);
    root = createRoot(container);
    calls = [];
    reports = [];
    session = signedIn;
    refusal = undefined;
    summary = null;
    overviews = 0;
    opened = [];
    vi.spyOn(HTMLElement.prototype, 'getBoundingClientRect').mockReturnValue({
        height: 117.4,
    } as DOMRect);
    mockIPC(
        (command, args) => {
            if (command === 'report_ready') {
                reports.push((args as { report: unknown }).report);
                return;
            }
            if (command === 'session') {
                return session;
            }
            if (command === 'overview') {
                overviews += 1;
                return summary;
            }
            if (command === 'open_main_window') {
                opened.push((args as { target?: string }).target);
            }
            calls.push(command);
            if (refusal && (command === 'unlock' || command === 'sign_in_again')) {
                return Promise.reject(refusal);
            }
        },
        { shouldMockEvents: true },
    );
    await show();
});

const show = () =>
    act(async () =>
        root.render(
            <AppInfoContext.Provider value={info}>
                <TraySummary />
            </AppInfoContext.Provider>,
        ),
    );

afterEach(async () => {
    await act(async () => root.unmount());
    container.remove();
    clearMocks();
    vi.restoreAllMocks();
});

const button = () => container.querySelector('button');
const buttons = () => [...container.querySelectorAll('button')].map((candidate) => candidate.textContent);
const press = (name: string) =>
    act(async () => [...container.querySelectorAll('button')].find((candidate) => candidate.textContent === name)?.click());
const checkedAt = new Date(2026, 5, 21, 10, 38).getTime();
const day = 24 * 60 * 60 * 1000;
const stand = (attention: AttentionItemView[], over: Partial<SummaryView> = {}): SummaryView => ({
    computedAt: checkedAt,
    checkedAt,
    listed: true,
    counts: { valid: 3, expiring: 2, expired: 2, notInIlm: 3 },
    attention,
    months: [0, 2, 0, 1, 0, 1, 0, 1, 0, 2, 0, 1],
    ...over,
});
const revoked: AttentionItemView = { kind: 'revoked', fingerprint: 'FP:build', name: 'Build server' };
const expired: AttentionItemView = { kind: 'expired', fingerprint: 'FP:card', name: 'Smart card login', on: checkedAt - 7 * day };
const expiring: AttentionItemView = {
    kind: 'expiring',
    fingerprint: 'FP:vpn',
    name: 'vpn.example.com',
    days: 13,
    on: checkedAt + 13 * day,
};
const unmatched: AttentionItemView = { kind: 'notInIlm', count: 3 };
const changeTo = (view: SessionView) => act(async () => emit('session-changed', view));

test('shows the name and the version under one heading', () => {
    expect(container.querySelectorAll('h1')).toHaveLength(1);
    expect(container.querySelector('h1')?.textContent).toBe(info.name);
    expect(container.textContent).toContain(strings.version(info.version));
});

test('has one button, named Open Identity Manager, that opens the main window', async () => {
    expect(buttons()).toEqual([strings.openApp]);

    await act(async () => button()?.click());

    expect(calls).toEqual(['open_main_window']);
    expect(opened).toEqual([null]);
});

test('Escape hides the summary and other keys do not', async () => {
    await act(async () => {
        document.dispatchEvent(new KeyboardEvent('keydown', { key: 'a', bubbles: true }));
    });
    expect(calls).toEqual([]);

    await act(async () => {
        document.dispatchEvent(new KeyboardEvent('keydown', { key: 'Escape', bubbles: true }));
    });

    expect(calls).toEqual(['hide_summary']);
});

test('focus starts on the button and returns to it when the window regains focus', async () => {
    expect(document.activeElement).toBe(button());

    (document.activeElement as HTMLElement).blur();
    await act(async () => {
        window.dispatchEvent(new Event('focus'));
    });

    expect(document.activeElement).toBe(button());
});

const shows = async (view: SummaryView | null) => {
    summary = view;
    await act(async () => root.render(null));
    await show();
};
const items = () => [...container.querySelectorAll<HTMLElement>('button[data-item]')];
const counts = () => [...container.querySelectorAll('ul[aria-label="Certificates by state"] li')].map((item) => item.textContent);

test('with a summary it shows the four counts, the first three items and how many more', async () => {
    await shows(stand([revoked, expired, expiring, unmatched]));

    expect(counts()).toEqual(['3Valid', '2Expiring soon', '2Expired', '3Not in ILM']);
    expect(items().map((item) => item.textContent)).toEqual([
        `Build server${strings.revokedInIlm}`,
        `Smart card login${strings.expiredOnDate(strings.date(expired.on))}`,
        `vpn.example.com${strings.expiresOnDate(strings.date(expiring.on), 13)}`,
    ]);
    expect(container.textContent).toContain('+1 more');
    expect(container.textContent).toContain(strings.lastCheckedWithIlm(checkedAt));
    expect(container.textContent).toContain(strings.needsAttention);
});

test('the counts leave out Not in ILM when certificates are not listed', async () => {
    await shows(stand([], { counts: { valid: 3, expiring: 0, expired: 0, notInIlm: null }, listed: false }));

    expect(counts()).toEqual(['3Valid', '0Expiring soon', '0Expired']);
    expect(items()).toEqual([]);
    expect(container.textContent).not.toContain('more');
    expect(container.textContent).not.toContain(strings.needsAttention);
});

test('Open Identity Manager keeps the focus whatever the items are', async () => {
    await shows(stand([revoked]));

    expect(document.activeElement?.textContent).toBe(strings.openApp);
});

test('an item opens the main window at its certificate; the not-in-ILM item opens Overview', async () => {
    await shows(stand([revoked, unmatched]));

    await act(async () => items()[0]?.click());
    await act(async () => items()[1]?.click());

    expect(opened).toEqual(['FP:build', 'overview']);
    expect(items()[1]?.textContent).toBe(strings.notInIlmCountShort(3));
});

test('only not-in-ILM items do not make the sign-in line say that attention is needed', async () => {
    await shows(stand([unmatched]));

    expect(container.textContent).not.toContain(strings.needsAttention);
    expect(container.textContent).toContain(strings.notInIlmCountShort(3));
});

test('requests in progress are listed, open Overview, and alone do not make the sign-in line say attention is needed', async () => {
    await shows(stand([{ kind: 'waiting', label: 'User mTLS', state: 'pendingApproval' }]));

    expect(container.textContent).not.toContain(strings.needsAttention);
    expect(items()[0]?.textContent).toBe(`User mTLS${strings.waitingForApproval}`);
    await act(async () => items()[0]?.click());
    expect(opened).toEqual(['overview']);
});

test('a request waiting for the approval is listed with its kind, opens the requests, and alone needs no attention', async () => {
    await shows(stand([{ kind: 'approval', uuid: 'a-1', name: 'S/MIME email', action: 'renew' }]));

    expect(container.textContent).not.toContain(strings.needsAttention);
    expect(items()[0]?.textContent).toBe(`S/MIME email${strings.approvalKinds.renew}`);
    await act(async () => items()[0]?.click());
    expect(opened).toEqual(['requests']);
});

test('on Linux a request waiting for the approval is left out of the summary', async () => {
    summary = stand([{ kind: 'approval', uuid: 'a-1', name: 'S/MIME email', action: 'renew' }, expired]);
    await act(async () => root.render(null));
    await act(async () =>
        root.render(
            <AppInfoContext.Provider value={{ ...info, platform: 'linux' }}>
                <TraySummary />
            </AppInfoContext.Provider>,
        ),
    );

    expect(items()).toHaveLength(1);
    expect(items()[0]?.textContent).toContain('Smart card login');
    expect(container.textContent).not.toContain('S/MIME email');
});

test('an approval keeps the focus when an item before it is removed', async () => {
    const approval: AttentionItemView = { kind: 'approval', uuid: 'a-1', name: 'S/MIME email', action: 'renew' };
    await shows(stand([revoked, approval]));
    items()[1]?.focus();
    const focused = document.activeElement;
    summary = stand([approval]);

    await act(async () => emit('inventory-changed'));

    expect(items()).toHaveLength(1);
    expect(document.activeElement).toBe(focused);
});

test('a revoked certificate makes the line say attention is needed even beside requests in progress', async () => {
    await shows(stand([revoked, { kind: 'waiting', label: 'Code signing', state: 'beingIssued' }]));

    expect(container.textContent).toContain(strings.needsAttention);
    expect(items()[1]?.textContent).toBe(`Code signing${strings.beingIssued}`);
});

test('a failure to open the main window is not an error', async () => {
    await shows(stand([revoked]));
    mockIPC(() => Promise.reject('refused'), { shouldMockEvents: true });

    await act(async () => items()[0]?.click());

    expect(items()).toHaveLength(1);
});

test('out of reach it shows the last counts and says when they are from', async () => {
    session = { ...signedIn, unreachable: true };
    await shows(stand([revoked]));

    expect(container.textContent).toContain(strings.cannotReachIlmSince(checkedAt));
    expect(container.textContent).not.toContain(strings.lastCheckedWithIlm(checkedAt));
    expect(counts()).toHaveLength(4);
});

test('out of reach before any check it only says so', async () => {
    session = { state: 'unreachable', address: 'ilm.internal', problem: 'timed out' };
    await shows(stand([], { checkedAt: null }));

    expect(container.textContent).toContain(strings.cannotReachIlm);
});

test('before the first check it names no time', async () => {
    await shows(stand([], { checkedAt: null }));

    expect(container.textContent).not.toContain('Last checked');
});

test('is read again when the inventory changes', async () => {
    await shows(stand([]));
    const before = overviews;
    summary = stand([revoked]);

    await act(async () => emit('inventory-changed'));

    expect(overviews).toBeGreaterThan(before);
    expect(items()).toHaveLength(1);
});

test('an item the person moved to keeps the focus when the inventory changes', async () => {
    await shows(stand([revoked, expired]));
    items()[1]?.focus();
    summary = stand([revoked, expired, expiring]);

    await act(async () => emit('inventory-changed'));

    expect(items()).toHaveLength(3);
    expect(document.activeElement).toBe(items()[1]);
});

test('a certificate keeps the focus when an item before it is removed', async () => {
    await shows(stand([revoked, expired]));
    items()[1]?.focus();
    const focused = document.activeElement;
    summary = stand([expired]);

    await act(async () => emit('inventory-changed'));

    expect(items()).toHaveLength(1);
    expect(document.activeElement).toBe(focused);
});

test('shows no counts or names when the summary is refused or there is none', async () => {
    summary = null;
    await shows(null);
    expect(container.querySelector('ul')).toBeNull();

    mockIPC((command) => (command === 'session' ? session : command === 'overview' ? Promise.reject('locked') : undefined), {
        shouldMockEvents: true,
    });
    await act(async () => root.render(null));
    await show();
    expect(container.querySelector('ul')).toBeNull();
});

test('locked or signed out, it asks for nothing and shows no counts or names', async () => {
    await shows(stand([revoked]));
    expect(counts()).toHaveLength(4);
    overviews = 0;

    await changeTo({ state: 'locked' });
    expect(overviews).toBe(0);
    expect(counts()).toEqual([]);
    expect(container.textContent).not.toContain('Build server');

    await changeTo(signedOut);
    expect(counts()).toEqual([]);
    expect(container.textContent).not.toContain('Build server');
    expect(overviews).toBe(0);
});

test('stops listening once it is gone', async () => {
    await act(async () => root.render(null));

    await act(async () => {
        document.dispatchEvent(new KeyboardEvent('keydown', { key: 'Escape', bubbles: true }));
    });

    expect(calls).toEqual([]);
});

test('its surface fills the window so no system shows its default background below it', () => {
    expect(container.firstElementChild?.classList.contains('min-h-screen')).toBe(true);
});

test('reports what it shows with the natural height of its content, rounded up', () => {
    expect(reports.at(-1)).toEqual({ ...info, height: 118 });
});

test('reports again when the session changes the content', async () => {
    const before = reports.length;

    await changeTo({ state: 'locked' });

    expect(reports.length).toBeGreaterThan(before);
});

test('reports no height when the content has none to measure', async () => {
    await act(async () => root.unmount());
    reports = [];
    vi.spyOn(HTMLElement.prototype, 'getBoundingClientRect').mockReturnValue({
        height: 0,
    } as DOMRect);
    root = createRoot(container);
    await show();

    expect(reports.at(-1)).toEqual(info);
});

test('signed in, it says where and as whom, with Open as the only button', () => {
    expect(container.textContent).toContain(strings.summarySignedIn('develop-02.example.com', 'Alex Morgan'));
    expect(buttons()).toEqual([strings.openApp]);
});

test('signed in but out of reach, it says it cannot reach the host', async () => {
    await changeTo({ ...signedIn, unreachable: true });

    expect(container.textContent).toContain(strings.summaryUnreachable('develop-02.example.com'));
    expect(container.textContent).not.toContain('Alex Morgan');
});

test('unreachable at start says it cannot reach the host and keeps the address when it is not a URL', async () => {
    await changeTo({ state: 'unreachable', address: 'ilm.internal', problem: 'timed out' });

    expect(container.textContent).toContain(strings.summaryUnreachable('ilm.internal'));
    expect(buttons()).toEqual([strings.openApp]);
});

test('signed out, it says so with the problem and offers no action', async () => {
    await changeTo({ ...signedOut, problem: 'Your sign-in has ended.' });

    expect(container.textContent).toContain(strings.signedOutTitle);
    expect(container.textContent).toContain('Your sign-in has ended.');
    expect(buttons()).toEqual([strings.openApp]);
});

test('signed out without a problem says only that', async () => {
    await changeTo(signedOut);

    expect(container.textContent).toContain(strings.signedOutTitle);
    expect(container.querySelector('.text-bad')).toBeNull();
});

test('an ended sign-in offers Sign in again above Open, which takes focus', async () => {
    await changeTo({ ...signedOut, problem: 'Your sign-in has ended.', again: true });

    expect(buttons()).toEqual([strings.signInAgain, strings.openApp]);
    expect(document.activeElement).toBe(button());

    await press(strings.signInAgain);

    expect(calls).toEqual(['sign_in_again']);
});

test('locked, it says so and offers Unlock above Open', async () => {
    await changeTo({ state: 'locked' });

    expect(container.textContent).toContain(strings.lockedTitle);
    expect(container.textContent).not.toContain('Alex Morgan');
    expect(buttons()).toEqual([strings.unlock, strings.openApp]);

    await press(strings.unlock);

    expect(calls).toEqual(['unlock']);
});

test('a refused action is not an error for the summary', async () => {
    refusal = 'Unlock was cancelled.';
    await changeTo({ state: 'locked' });

    await press(strings.unlock);

    expect(container.textContent).toContain(strings.lockedTitle);
});

test('says nothing about the sign-in while it starts', async () => {
    await changeTo({ state: 'starting' });

    expect(container.querySelectorAll('p')).toHaveLength(1);
});
