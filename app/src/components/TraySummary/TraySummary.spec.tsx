import { clearMocks, mockIPC } from '@tauri-apps/api/mocks';
import { act } from 'react';
import { createRoot, type Root } from 'react-dom/client';
import { afterEach, beforeEach, expect, test, vi } from 'vitest';
import { AppInfoContext } from '../../app-info';
import type { AppInfo } from '../../bridge';
import { strings } from '../../strings';
import { TraySummary } from './TraySummary';

const info: AppInfo = {
    name: 'Identity Manager',
    version: '0.1.0',
    platform: 'macos',
};

let container: HTMLElement;
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
    vi.spyOn(HTMLElement.prototype, 'getBoundingClientRect').mockReturnValue({
        height: 117.4,
    } as DOMRect);
    mockIPC((command, args) => {
        if (command === 'report_ready') {
            reports.push((args as { report: unknown }).report);
            return;
        }
        calls.push(command);
    });
    await act(async () =>
        root.render(
            <AppInfoContext.Provider value={info}>
                <TraySummary />
            </AppInfoContext.Provider>,
        ),
    );
});

afterEach(async () => {
    await act(async () => root.unmount());
    container.remove();
    clearMocks();
    vi.restoreAllMocks();
});

const button = () => container.querySelector('button');

test('shows the name and the version under one heading', () => {
    expect(container.querySelectorAll('h1')).toHaveLength(1);
    expect(container.querySelector('h1')?.textContent).toBe(info.name);
    expect(container.textContent).toContain(strings.version(info.version));
});

test('has one button, named Open Identity Manager, that opens the main window', async () => {
    expect(container.querySelectorAll('button')).toHaveLength(1);
    expect(button()?.textContent).toBe(strings.openApp);

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
    expect(reports).toEqual([{ ...info, height: 118 }]);
});

test('reports no height when the content has none to measure', async () => {
    await act(async () => root.unmount());
    reports = [];
    vi.spyOn(HTMLElement.prototype, 'getBoundingClientRect').mockReturnValue({
        height: 0,
    } as DOMRect);
    root = createRoot(container);
    await act(async () =>
        root.render(
            <AppInfoContext.Provider value={info}>
                <TraySummary />
            </AppInfoContext.Provider>,
        ),
    );

    expect(reports).toEqual([info]);
});
