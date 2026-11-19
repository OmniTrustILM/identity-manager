import { emit } from '@tauri-apps/api/event';
import { clearMocks, mockIPC } from '@tauri-apps/api/mocks';
import { act } from 'react';
import { createRoot, type Root } from 'react-dom/client';
import { afterEach, beforeEach, expect, test, vi } from 'vitest';
import { AppInfoContext } from '../../app-info';
import type { AppInfo, SessionView } from '../../bridge';
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
