import { clearMocks, mockIPC } from '@tauri-apps/api/mocks';
import { StrictMode } from 'react';
import { act } from 'react';
import { createRoot, type Root } from 'react-dom/client';
import { afterEach, beforeEach, expect, test } from 'vitest';
import { App } from './App';
import { strings } from './strings';

const info = { name: 'Identity Manager', version: '0.1.0' };

let container: HTMLElement;
let root: Root;
let reports: unknown[];

beforeEach(() => {
    (globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true;
    container = document.createElement('div');
    document.body.append(container);
    root = createRoot(container);
    reports = [];
});

afterEach(() => {
    act(() => root.unmount());
    container.remove();
    clearMocks();
});

function mockBridge(appInfo: () => unknown) {
    mockIPC((command, args) => {
        if (command === 'app_info') {
            return appInfo();
        }
        reports.push((args as { report: unknown }).report);
    });
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
