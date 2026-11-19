import { clearMocks, mockIPC, mockWindows } from '@tauri-apps/api/mocks';
import { act } from 'react';
import { createRoot, type Root } from 'react-dom/client';
import { afterEach, beforeEach, expect, test, vi } from 'vitest';
import { LockIcon, SettingsIcon } from '../design-system/icons';
import { type Pane, SettingsTabs } from './SettingsTabs';

const panes: [Pane, ...Pane[]] = [
    { id: 'general', title: 'General', icon: SettingsIcon, content: <p>General content</p> },
    { id: 'security', title: 'Security', icon: LockIcon, content: <p>Security content</p> },
    { id: 'connection', title: 'Connection', icon: LockIcon, content: <p>Connection content</p> },
];

let container: HTMLElement;
let root: Root;
let titles: unknown[];

beforeEach(() => {
    (globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true;
    container = document.createElement('div');
    document.body.append(container);
    root = createRoot(container);
    titles = [];
    localStorage.clear();
    mockWindows('settings');
    mockIPC((command, args) => {
        if (command === 'plugin:window|set_title') {
            titles.push((args as { value: unknown }).value);
        }
    });
});

afterEach(async () => {
    await act(async () => root.unmount());
    container.remove();
    clearMocks();
    vi.restoreAllMocks();
});

async function render(list: [Pane, ...Pane[]] = panes) {
    await act(async () => root.render(<SettingsTabs panes={list} />));
}

const tabs = () => [...container.querySelectorAll<HTMLButtonElement>('[role="tab"]')];
const selected = () => tabs().find((tab) => tab.getAttribute('aria-selected') === 'true');
const panel = () => container.querySelector('[role="tabpanel"]');

test('shows a tab for each pane and the first pane, named in the window title', async () => {
    await render();

    expect(tabs().map((tab) => tab.textContent)).toEqual(['General', 'Security', 'Connection']);
    expect(selected()?.textContent).toBe('General');
    expect(panel()?.textContent).toBe('General content');
    expect(panel()?.getAttribute('aria-labelledby')).toBe(selected()?.id);
    expect(selected()?.getAttribute('aria-controls')).toBe(panel()?.id);
    expect(tabs().map((tab) => tab.tabIndex)).toEqual([0, -1, -1]);
    expect(titles).toEqual(['General']);
});

test('the toolbar moves the window and its tabs stay clickable', async () => {
    await render();

    expect(container.querySelector('[role="tablist"]')?.getAttribute('data-tauri-drag-region')).toBe('deep');
});

test('a click shows the pane, names the window after it and is remembered', async () => {
    await render();

    await act(async () => tabs()[1]?.click());

    expect(panel()?.textContent).toBe('Security content');
    expect(titles).toEqual(['General', 'Security']);
    expect(localStorage.getItem('settings-pane')).toBe('security');
});

test('opens on the remembered pane, and on the first when that pane is gone', async () => {
    localStorage.setItem('settings-pane', 'connection');
    await render();
    expect(panel()?.textContent).toBe('Connection content');

    await act(async () => root.unmount());
    root = createRoot(container);
    await render([panes[0], panes[1] as Pane]);
    expect(panel()?.textContent).toBe('General content');
});

test('a pane that goes away is forgotten and does not come back by itself', async () => {
    localStorage.setItem('settings-pane', 'connection');
    await render();
    await render([panes[0], panes[1] as Pane]);
    expect(panel()?.textContent).toBe('General content');

    await render();
    expect(panel()?.textContent).toBe('General content');
});

test('the arrow keys, Home and End move between the tabs and show their panes', async () => {
    await render();
    const press = async (key: string) =>
        act(async () => {
            document.activeElement?.dispatchEvent(new KeyboardEvent('keydown', { key, bubbles: true }));
        });
    tabs()[0]?.focus();

    await press('ArrowRight');
    expect(document.activeElement?.textContent).toBe('Security');
    expect(panel()?.textContent).toBe('Security content');

    await press('End');
    await press('ArrowRight');
    expect(document.activeElement?.textContent).toBe('Connection');

    await press('ArrowLeft');
    expect(document.activeElement?.textContent).toBe('Security');

    await press('Home');
    await press('ArrowLeft');
    expect(document.activeElement?.textContent).toBe('General');

    await press('a');
    expect(panel()?.textContent).toBe('General content');
});

test('works without storage', async () => {
    vi.spyOn(Storage.prototype, 'getItem').mockImplementation(() => {
        throw new Error('blocked');
    });
    vi.spyOn(Storage.prototype, 'setItem').mockImplementation(() => {
        throw new Error('blocked');
    });
    await render();

    await act(async () => tabs()[2]?.click());

    expect(panel()?.textContent).toBe('Connection content');
});
