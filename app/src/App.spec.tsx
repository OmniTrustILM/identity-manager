import { emit } from '@tauri-apps/api/event';
import { clearMocks, mockIPC, mockWindows } from '@tauri-apps/api/mocks';
import { StrictMode } from 'react';
import { act } from 'react';
import { createRoot, type Root } from 'react-dom/client';
import { afterEach, beforeEach, expect, test, vi } from 'vitest';
import { App } from './App';
import type { SessionView } from './bridge';
import { strings } from './strings';

const info = {
    name: 'Identity Manager',
    version: '0.1.0',
    platform: 'macos' as const,
};

let container: HTMLElement;
let root: Root;
let reports: unknown[];

beforeEach(() => {
    (globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true;
    container = document.createElement('div');
    document.body.append(container);
    root = createRoot(container);
    reports = [];
    schemeRequests = 0;
    delete document.documentElement.dataset.os;
    delete document.documentElement.dataset.theme;
});

afterEach(async () => {
    await act(async () => root.unmount());
    container.remove();
    clearMocks();
});

let schemeRequests: number;

const signedIn: SessionView = {
    state: 'signedIn',
    address: 'https://ilm.example.com',
    person: { name: 'Alex Morgan', username: 'alex.morgan' },
    allowedListings: ['certificates'],
    certificate: null,
    unreachable: false,
};

function mockBridge(
    appInfo: () => unknown,
    scheme: string | null = null,
    label = 'main',
    session: () => unknown = () => signedIn,
    unlocking: () => unknown = () => undefined,
) {
    mockWindows(label);
    mockIPC(
        (command, args) => {
            if (command === 'app_info') {
                return appInfo();
            }
            if (command === 'settings') {
                return {
                    startAtLogin: { value: true, locked: false },
                    logLevel: { value: 'info', locked: true },
                    ilmUrl: { value: 'https://ilm.example.com', locked: false },
                    requireUnlock: { value: true, locked: false },
                    lockAfterIdle: { value: null, locked: false },
                    unlock: 'unsupported',
                };
            }
            if (command === 'unlock') {
                return unlocking();
            }
            if (command === 'session') {
                return session();
            }
            if (command === 'color_scheme') {
                schemeRequests += 1;
                return scheme;
            }
            if (command === 'report_ready') {
                reports.push((args as { report: unknown }).report);
            }
        },
        { shouldMockEvents: true },
    );
}

async function render(element: React.ReactElement) {
    await act(async () => {
        root.render(element);
    });
}

test('shows the product name and version and reports exactly what it shows', async () => {
    mockBridge(() => info);

    await render(<App />);

    expect(container.querySelectorAll('h1')).toHaveLength(1);
    expect(container.querySelector('h1')?.textContent).toBe(info.name);
    expect(container.textContent).toContain(strings.version(info.version));
    expect(reports).toEqual([info]);
});

test('reports once under StrictMode double effects', async () => {
    mockBridge(() => info);

    await render(
        <StrictMode>
            <App />
        </StrictMode>,
    );

    expect(container.querySelector('h1')?.textContent).toBe(info.name);
    expect(reports).toEqual([info]);
});

test('shows the load error and reports nothing when the app information is unavailable', async () => {
    mockBridge(() => {
        throw new Error('no bridge');
    });

    await render(<App />);

    expect(container.textContent).toContain(strings.loadError);
    expect(container.querySelector('h1')).toBeNull();
    expect(reports).toEqual([]);
});

test.each(['macos', 'windows', 'linux'] as const)('sets data-os to the %s platform before showing the content', async (platform) => {
    mockBridge(() => ({ ...info, platform }));

    await render(<App />);

    expect(document.documentElement.dataset.os).toBe(platform);
    expect(container.querySelector('h1')?.textContent).toBe(info.name);
});

test('leaves data-os unset when the app information is unavailable', async () => {
    mockBridge(() => {
        throw new Error('no bridge');
    });

    await render(<App />);

    expect(document.documentElement.dataset.os).toBeUndefined();
});

test('on Linux follows the colour scheme of the desktop', async () => {
    mockBridge(() => ({ ...info, platform: 'linux' }), 'dark');

    await render(<App />);

    expect(document.documentElement.dataset.theme).toBe('dark');
});

test.each(['macos', 'windows'] as const)('on %s leaves the colour scheme to the web view', async (platform) => {
    mockBridge(() => ({ ...info, platform }), 'dark');

    await render(<App />);

    expect(schemeRequests).toBe(0);
    expect(document.documentElement.dataset.theme).toBeUndefined();
});

test('the main window shows the shell, not the summary', async () => {
    mockBridge(() => info);

    await render(<App />);

    expect(container.querySelector('nav')).not.toBeNull();
    expect(container.querySelector('button')?.textContent).not.toBe(strings.openApp);
});

test('the summary window shows the name, the version and the open button instead of the shell', async () => {
    mockBridge(() => info, null, 'summary');

    await render(<App />);

    expect(container.querySelector('nav')).toBeNull();
    expect(container.querySelector('h1')?.textContent).toBe(info.name);
    expect(container.textContent).toContain(strings.version(info.version));
    expect(container.querySelector('button')?.textContent).toBe(strings.openApp);
});

test('both windows report what they show, the summary with the height of its content and main with none', async () => {
    vi.spyOn(HTMLElement.prototype, 'getBoundingClientRect').mockReturnValue({
        height: 120,
    } as DOMRect);
    for (const [label, expected] of [
        ['main', info],
        ['summary', { ...info, height: 120 }],
    ] as const) {
        reports = [];
        mockBridge(() => info, null, label);
        await render(<App />);
        expect(reports.at(-1)).toEqual(expected);
        await act(async () => root.render(null));
        clearMocks();
    }
    vi.restoreAllMocks();
});

test('the settings window shows Settings as its root, without the shell, and reports nothing', async () => {
    mockBridge(() => info, null, 'settings');

    await render(<App />);

    expect(container.querySelector('nav')).toBeNull();
    expect(container.querySelector('h2')?.textContent).toBe(strings.general);
    expect(container.querySelector('select')?.disabled).toBe(true);
    expect(reports).toEqual([]);
});

test.each([
    ['windows', 'Settings'],
    ['linux', 'Preferences'],
] as const)('on %s the main window has the %s entry at the bottom of the sidebar', async (platform, word) => {
    mockBridge(() => ({ ...info, platform }));

    await render(<App />);

    expect(container.querySelector('nav > div button')?.textContent).toBe(word);
});

test('on macOS the main window has no Settings entry', async () => {
    mockBridge(() => info);

    await render(<App />);

    expect(container.querySelector('nav > div')).toBeNull();
});

const mainWith = (session: () => unknown) => mockBridge(() => info, null, 'main', session);
const signedOut: SessionView = { state: 'signedOut', address: null, locked: false, problem: null, again: false };

test('while the session starts the main window shows nothing to use but still reports', async () => {
    mainWith(() => ({ state: 'starting' }));

    await render(<App />);

    expect(container.querySelector('button')).toBeNull();
    expect(container.querySelector('input')).toBeNull();
    expect(container.querySelector('nav')).toBeNull();
    expect(reports).toEqual([info]);
});

test('signed out without an address the main window shows Connect, not the shell', async () => {
    mainWith(() => signedOut);

    await render(<App />);

    expect(container.querySelector('h1')?.textContent).toBe(strings.connectTitle);
    expect(container.querySelector('nav')).toBeNull();
});

test('signed out with the address of the organization the main window shows Welcome', async () => {
    mainWith(() => ({ ...signedOut, address: 'https://ilm.example.com', locked: true }));

    await render(<App />);

    expect(container.querySelector('h1')?.textContent).toBe(strings.welcomeTitle);
});

test('while the person signs in the main window shows Waiting', async () => {
    mainWith(() => ({ state: 'signingIn', provider: 'Company SSO' }));

    await render(<App />);

    expect(container.querySelector('h1')?.textContent).toBe(strings.waitingTitle);
});

test('session-changed switches between the sign-in and the shell', async () => {
    mainWith(() => signedOut);
    await render(<App />);

    await act(async () => emit('session-changed', signedIn));
    expect(container.querySelector('nav')).not.toBeNull();
    expect(container.querySelector('input')).toBeNull();

    await act(async () => emit('session-changed', signedOut));
    expect(container.querySelector('nav')).toBeNull();
    expect(container.querySelector('h1')?.textContent).toBe(strings.connectTitle);
});

test('a session that cannot be read is reported and shows nothing to use', async () => {
    mainWith(() => {
        throw new Error('no bridge');
    });

    await render(<App />);

    expect(container.querySelector('[role="alert"]')?.textContent).toBe(strings.sessionLoadError);
    expect(container.querySelector('nav')).toBeNull();
});

test('the summary window does not wait for the session', async () => {
    mockBridge(
        () => info,
        null,
        'summary',
        () => signedOut,
    );

    await render(<App />);

    expect(container.querySelector('button')?.textContent).toBe(strings.openApp);
});

test('a change announced while the session is still being read is not overwritten by that read', async () => {
    let answer: (view: SessionView) => void = () => undefined;
    mainWith(() => new Promise((resolve) => (answer = resolve)));
    await render(<App />);

    await act(async () => emit('session-changed', signedOut));
    await act(async () => answer(signedIn));

    expect(container.querySelector('h1')?.textContent).toBe(strings.connectTitle);
});

test('a change announced after the window is gone is ignored', async () => {
    mainWith(() => signedOut);
    await render(<App />);
    await act(async () => root.render(null));

    await act(async () => emit('session-changed', signedIn));

    expect(container.querySelector('nav')).toBeNull();
});

test('the sign-in still shows when the window cannot listen for changes', async () => {
    mockWindows('main');
    mockIPC((command) => {
        if (command === 'app_info') {
            return info;
        }
        if (command === 'session') {
            return signedOut;
        }
        if (command === 'plugin:event|listen') {
            return Promise.reject('refused');
        }
    });

    await render(<App />);

    expect(container.querySelector('h1')?.textContent).toBe(strings.connectTitle);
});

test('the session is read only once the window listens for its changes', async () => {
    let listening: (id: number) => void = () => undefined;
    const commands: string[] = [];
    mockWindows('main');
    mockIPC((command) => {
        commands.push(command);
        if (command === 'app_info') {
            return info;
        }
        if (command === 'session') {
            return signedOut;
        }
        if (command === 'plugin:event|listen') {
            return new Promise((resolve) => (listening = resolve));
        }
    });

    await render(<App />);
    expect(commands).not.toContain('session');

    await act(async () => listening(1));

    expect(commands).toContain('session');
    expect(container.querySelector('h1')?.textContent).toBe(strings.connectTitle);
});

test('locked, the main window shows Unlock and asks once, with nothing personal', async () => {
    let asked = 0;
    mockBridge(
        () => info,
        null,
        'main',
        () => ({ state: 'locked' }),
        () => asked++,
    );

    await render(<App />);

    expect(container.querySelector('h1')?.textContent).toBe(strings.lockedTitle);
    expect(container.querySelector('nav')).toBeNull();
    expect(asked).toBe(1);
});

test('unlocking in the main window brings back the shell', async () => {
    mockBridge(
        () => info,
        null,
        'main',
        () => ({ state: 'locked' }),
        () => undefined,
    );
    await render(<App />);

    await act(async () => emit('session-changed', signedIn));

    expect(container.querySelector('nav')).not.toBeNull();
});

test('unreachable, the main window shows the address and the problem', async () => {
    mainWith(() => ({ state: 'unreachable', address: 'https://ilm.example.com', problem: 'The connection timed out.' }));

    await render(<App />);

    expect(container.querySelector('h1')?.textContent).toBe(strings.unreachableTitle);
    expect(container.querySelector('[role="alert"]')?.textContent).toBe('The connection timed out.');
});

test('locked, the Settings window shows Unlock without asking', async () => {
    let asked = 0;
    mockBridge(
        () => info,
        null,
        'settings',
        () => ({ state: 'locked' }),
        () => asked++,
    );

    await render(<App />);

    expect(container.querySelector('h1')?.textContent).toBe(strings.lockedTitle);
    expect(asked).toBe(0);
});

test('locked, the summary names the state and offers Unlock', async () => {
    mockBridge(
        () => info,
        null,
        'summary',
        () => ({ state: 'locked' }),
    );

    await render(<App />);

    expect([...container.querySelectorAll('button')].map((candidate) => candidate.textContent)).toEqual([strings.unlock, strings.openApp]);
});
