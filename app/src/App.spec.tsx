import { clearMocks, mockIPC, mockWindows } from '@tauri-apps/api/mocks';
import { StrictMode } from 'react';
import { act } from 'react';
import { createRoot, type Root } from 'react-dom/client';
import { afterEach, beforeEach, expect, test, vi } from 'vitest';
import { App } from './App';
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

function mockBridge(appInfo: () => unknown, scheme: string | null = null, label = 'main') {
    mockWindows(label);
    mockIPC(
        (command, args) => {
            if (command === 'app_info') {
                return appInfo();
            }
            if (command === 'settings') {
                return { startAtLogin: { value: true, locked: false }, logLevel: { value: 'info', locked: true } };
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
        expect(reports).toEqual([expected]);
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
