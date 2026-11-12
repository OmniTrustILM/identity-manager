import { emit } from '@tauri-apps/api/event';
import { clearMocks, mockIPC } from '@tauri-apps/api/mocks';
import { act } from 'react';
import { createRoot, type Root } from 'react-dom/client';
import { afterEach, beforeEach, expect, test } from 'vitest';
import { AppInfoContext, useAppInfo } from '../../app-info';
import type { AppInfo } from '../../bridge';
import { OverviewIcon } from '../../design-system/icons';
import { type Section, sections, settingsSection } from '../../sections';
import { strings } from '../../strings';
import { Shell } from './Shell';

const info: AppInfo = { name: 'Identity Manager', version: '0.1.0', platform: 'macos' };
const other: Section = { id: 'other', label: 'Other', icon: OverviewIcon, Component: () => <p>Other content</p> };

const Probe = () => <p>{useAppInfo().name}</p>;

let container: HTMLElement;
let root: Root;

beforeEach(() => {
    (globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true;
    container = document.createElement('div');
    document.body.append(container);
    root = createRoot(container);
});

afterEach(async () => {
    await act(async () => root.unmount());
    container.remove();
    clearMocks();
});

async function render(list: Section[], platform: AppInfo['platform'] = 'macos', bottom?: Section) {
    await act(async () =>
        root.render(
            <AppInfoContext.Provider value={{ ...info, platform }}>
                <Shell sections={list} bottom={bottom} />
            </AppInfoContext.Provider>,
        ),
    );
}

const entries = () => [...container.querySelectorAll('nav button')];

test('lists exactly the registered sections and opens the first', async () => {
    await render(sections);

    expect(entries().map((entry) => entry.textContent)).toEqual(sections.map((section) => section.label));
    expect(entries()[0]?.getAttribute('aria-current')).toBe('page');
});

test('the overview shows the product name and version', async () => {
    await render(sections);

    expect(container.querySelector('h1')?.textContent).toBe(info.name);
    expect(container.textContent).toContain(strings.version(info.version));
});

test('selecting a section shows its content and marks it current', async () => {
    await render([...sections, other]);

    await act(async () => (entries()[1] as HTMLElement).click());

    expect(container.querySelector('main')?.textContent).toBe('Other content');
    expect(entries().map((entry) => entry.getAttribute('aria-current'))).toEqual([null, 'page']);
});

test('shows no content when no section is registered', async () => {
    await render([]);

    expect(entries()).toEqual([]);
    expect(container.querySelector('main')?.textContent).toBe('');
});

test('on Linux the product name heads the sidebar', async () => {
    await render(sections, 'linux');

    expect(container.querySelector('nav')?.textContent).toContain(info.name);
});

test.each(['macos', 'windows'] as const)('on %s the sidebar holds only the sections', async (platform) => {
    await render(sections, platform);

    expect(container.querySelector('nav')?.textContent).not.toContain(info.name);
});

test('the app information is required where it is read', async () => {
    const quiet = (event: ErrorEvent) => event.preventDefault();
    window.addEventListener('error', quiet);
    const log = console.error;
    console.error = () => undefined;

    await expect(act(async () => root.render(<Probe />))).rejects.toThrow('not available');

    console.error = log;
    window.removeEventListener('error', quiet);
});

const settingsEntry = () => container.querySelector('nav > div button') as HTMLElement | null;

test.each([
    ['windows', 'Settings'],
    ['linux', 'Preferences'],
] as const)('on %s the sidebar ends with a %s entry that opens the page', async (platform, word) => {
    mockIPC(() => ({ startAtLogin: { value: true, locked: false }, logLevel: { value: 'info', locked: false } }));

    await render(sections, platform, settingsSection(platform));

    expect(settingsEntry()?.textContent).toBe(word);
    await act(async () => settingsEntry()?.click());
    expect(settingsEntry()?.getAttribute('aria-current')).toBe('page');
    expect(container.querySelector('main h1')?.textContent).toBe(word);
});

test('macOS has no Settings entry in the sidebar', () => {
    expect(settingsSection('macos')).toBeUndefined();
});

const settingsView = { startAtLogin: { value: true, locked: false }, logLevel: { value: 'info', locked: false } };

/** Answers `pending_section` from a queue, one answer per call, `null` once it is empty. */
function mockRequests(...answers: (string | null)[]) {
    const queue = [...answers];
    mockIPC((command) => (command === 'pending_section' ? (queue.shift() ?? null) : settingsView), {
        shouldMockEvents: true,
    });
}

test('the request to open Settings selects the entry; other sections are not opened that way', async () => {
    mockRequests(null, 'other', 'settings');
    await render([...sections, other], 'windows', settingsSection('windows'));

    await act(async () => emit('open-section', 'settings'));
    expect(container.querySelector('main')?.textContent).not.toContain('Other content');
    expect(settingsEntry()?.getAttribute('aria-current')).toBeNull();

    await act(async () => emit('open-section', 'settings'));
    expect(settingsEntry()?.getAttribute('aria-current')).toBe('page');
    expect(container.querySelector('main h1')?.textContent).toBe('Settings');
});

test('a request made before the listener existed opens Settings at mount and is not reopened later', async () => {
    mockRequests('settings');
    await render(sections, 'windows', settingsSection('windows'));
    expect(settingsEntry()?.getAttribute('aria-current')).toBe('page');

    await act(async () => (entries()[0] as HTMLElement).click());
    await act(async () => root.render(null));
    await render(sections, 'windows', settingsSection('windows'));

    expect(settingsEntry()?.getAttribute('aria-current')).toBeNull();
    expect(entries()[0]?.getAttribute('aria-current')).toBe('page');
});

test('listens for the request only where there is a Settings entry, and stops on unmount', async () => {
    const listens: string[] = [];
    mockIPC((command, args) => {
        if (command === 'plugin:event|listen' || command === 'plugin:event|unlisten') {
            listens.push(command);
        }
        return (args as { handler?: number })?.handler;
    });
    await render(sections, 'macos');
    expect(listens).toEqual([]);

    await render(sections, 'windows', { ...other, id: 'settings' });
    expect(listens).toEqual(['plugin:event|listen']);

    await act(async () => root.render(null));
    expect(listens).toEqual(['plugin:event|listen', 'plugin:event|unlisten']);
});

test('works when the event bridge is not available', async () => {
    await render(sections, 'windows', { ...other, id: 'settings' });

    expect(settingsEntry()?.getAttribute('aria-current')).toBeNull();
});

test('stays where it is when the pending request cannot be read', async () => {
    mockIPC(
        (command) => {
            if (command === 'pending_section') {
                throw new Error('refused');
            }
        },
        { shouldMockEvents: true },
    );
    await render(sections, 'windows', settingsSection('windows'));

    expect(settingsEntry()?.getAttribute('aria-current')).toBeNull();
});
