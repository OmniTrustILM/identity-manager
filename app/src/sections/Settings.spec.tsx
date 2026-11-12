import { clearMocks, mockIPC } from '@tauri-apps/api/mocks';
import { act } from 'react';
import { createRoot, type Root } from 'react-dom/client';
import { afterEach, beforeEach, expect, test } from 'vitest';
import { AppInfoContext } from '../app-info';
import type { AppInfo, Change, SettingsView } from '../bridge';
import { strings } from '../strings';
import { Settings } from './Settings';

const open: SettingsView = {
    startAtLogin: { value: true, locked: false },
    logLevel: { value: 'info', locked: false },
};
const lockedLevel: SettingsView = { ...open, logLevel: { value: 'debug', locked: true } };

let container: HTMLElement;
let root: Root;
let calls: { command: string; args: unknown }[];

beforeEach(() => {
    (globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true;
    container = document.createElement('div');
    document.body.append(container);
    root = createRoot(container);
    calls = [];
});

afterEach(async () => {
    await act(async () => root.unmount());
    container.remove();
    clearMocks();
});

type Handler = (command: string, args: unknown) => unknown;

function bridge(handler: Handler) {
    mockIPC((command, args) => {
        calls.push({ command, args });
        return handler(command, args);
    });
}

async function render(platform: AppInfo['platform'] = 'macos') {
    await act(async () =>
        root.render(
            <AppInfoContext.Provider value={{ name: 'Identity Manager', version: '0.1.0', platform }}>
                <Settings />
            </AppInfoContext.Provider>,
        ),
    );
}

const toggle = () => container.querySelector('input[role="switch"]') as HTMLInputElement;
const select = () => container.querySelector('select') as HTMLSelectElement;
const alerts = () => [...container.querySelectorAll('[role="alert"]')].map((alert) => alert.textContent);

async function chooseLevel(level: string) {
    await act(async () => {
        select().value = level;
        select().dispatchEvent(new Event('change', { bubbles: true }));
    });
}

test('shows the group General with a labelled switch and select from the view', async () => {
    bridge(() => ({ ...open, startAtLogin: { value: false, locked: false } }));

    await render();

    expect(container.querySelector('section')?.getAttribute('aria-labelledby')).toBe(container.querySelector('h2')?.id);
    expect(container.querySelector('h2')?.textContent).toBe(strings.general);
    expect(container.querySelector(`label[for="${toggle().id}"]`)?.textContent).toBe(strings.startAtLogin);
    expect(toggle().checked).toBe(false);
    expect(container.querySelector(`label[for="${select().id}"]`)?.textContent).toBe(strings.logLevel);
    expect([...select().options].map((option) => option.value)).toEqual(['error', 'warn', 'info', 'debug']);
    expect(select().value).toBe('info');
    expect(container.textContent).not.toContain(strings.managedByOrganization);
    expect(calls).toEqual([{ command: 'settings', args: {} }]);
});

test('changing the switch sends the change and shows the view that comes back', async () => {
    bridge((command) => (command === 'set_setting' ? { ...open, startAtLogin: { value: false, locked: false } } : open));
    await render();

    await act(async () => toggle().click());

    expect(calls.at(-1)).toEqual({ command: 'set_setting', args: { change: { key: 'startAtLogin', value: false } satisfies Change } });
    expect(toggle().checked).toBe(false);
});

test('changing the select sends the level', async () => {
    bridge((command, args) =>
        command === 'set_setting'
            ? { ...open, logLevel: { value: (args as { change: { value: 'warn' } }).change.value, locked: false } }
            : open,
    );
    await render();

    await chooseLevel('warn');

    expect(calls.at(-1)).toEqual({ command: 'set_setting', args: { change: { key: 'logLevel', value: 'warn' } } });
    expect(select().value).toBe('warn');
});

test('a locked row disables its control and points at the lock note', async () => {
    bridge(() => lockedLevel);

    await render();

    expect(select().disabled).toBe(true);
    const note = document.getElementById(select().getAttribute('aria-describedby') ?? '');
    expect(note?.textContent).toBe(strings.managedByOrganization);
    expect(toggle().disabled).toBe(false);
    expect(toggle().hasAttribute('aria-describedby')).toBe(false);
    expect(container.textContent?.split(strings.managedByOrganization)).toHaveLength(2);
});

test('a refused change shows the error under its row, reloads the view and keeps the error away from the other row', async () => {
    let level: SettingsView = open;
    bridge((command) => {
        if (command === 'set_setting') {
            level = lockedLevel;
            return Promise.reject('LogLevel is managed by your organization');
        }
        return level;
    });
    await render();

    await chooseLevel('warn');

    expect(alerts()).toEqual(['LogLevel is managed by your organization']);
    expect(select().closest('div[class*="border-separator"]')?.contains(container.querySelector('[role="alert"]'))).toBe(true);
    expect(select().disabled).toBe(true);
    expect(select().value).toBe('debug');
    expect(select().getAttribute('aria-describedby')?.split(' ')).toHaveLength(2);
    expect(calls.filter((call) => call.command === 'settings')).toHaveLength(2);
});

test('a later success clears the error of that row', async () => {
    let fail = true;
    bridge((command) => {
        if (command === 'set_setting' && fail) {
            return Promise.reject('no');
        }
        return open;
    });
    await render();
    await act(async () => toggle().click());
    expect(alerts()).toEqual(['no']);

    fail = false;
    await act(async () => toggle().click());

    expect(alerts()).toEqual([]);
    expect(toggle().hasAttribute('aria-describedby')).toBe(false);
});

test('a refusal without text still says that the setting could not be changed', async () => {
    bridge((command) => (command === 'set_setting' ? Promise.reject('') : open));
    await render();

    await act(async () => toggle().click());

    expect(alerts()).toEqual([strings.settingFailed]);
});

test('keeps the view when the reload after a refusal fails too', async () => {
    let reloads = 0;
    bridge((command) => {
        if (command === 'set_setting') {
            return Promise.reject('no');
        }
        reloads += 1;
        return reloads === 1 ? open : Promise.reject('gone');
    });
    await render();

    await act(async () => toggle().click());

    expect(alerts()).toEqual(['no']);
    expect(toggle().checked).toBe(true);
});

test('shows the load error when the settings are unavailable', async () => {
    bridge(() => Promise.reject('no bridge'));

    await render();

    expect(alerts()).toEqual([strings.settingsLoadError]);
    expect(container.querySelector('select')).toBeNull();
});

test('clears the load error when a reload on focus succeeds', async () => {
    let available = false;
    bridge(() => (available ? open : Promise.reject('no bridge')));
    await render();

    available = true;
    await act(async () => {
        window.dispatchEvent(new Event('focus'));
    });

    expect(alerts()).toEqual([]);
    expect(select().disabled).toBe(false);
});

test('shows nothing and no error before the settings arrive, and nothing after unmounting', async () => {
    let answer: (view: SettingsView) => void = () => undefined;
    bridge(() => new Promise((resolve) => (answer = resolve)));
    await render();

    expect(container.innerHTML).toBe('');

    await act(async () => root.render(null));
    await act(async () => answer(open));

    expect(container.innerHTML).toBe('');
});

test('reloads the view when the window gains focus and stops after unmounting', async () => {
    let view = lockedLevel;
    bridge(() => view);
    await render();
    expect(select().disabled).toBe(true);

    view = open;
    await act(async () => {
        window.dispatchEvent(new Event('focus'));
    });

    expect(select().disabled).toBe(false);

    await act(async () => root.render(null));
    const before = calls.length;
    window.dispatchEvent(new Event('focus'));

    expect(calls).toHaveLength(before);
});

test('ignores a load error that comes after unmounting', async () => {
    let fail: (reason: string) => void = () => undefined;
    bridge(() => new Promise((_, reject) => (fail = reject)));
    await render();

    await act(async () => root.render(null));
    await act(async () => fail('late'));

    expect(container.innerHTML).toBe('');
});

test('on macOS the window carries the title, so the content has no heading', async () => {
    bridge(() => open);

    await render('macos');

    expect(container.querySelector('h1')).toBeNull();
});

test.each([
    ['windows', strings.settings],
    ['linux', strings.preferences],
] as const)('on %s the page has the heading %s', async (platform, heading) => {
    bridge(() => open);

    await render(platform);

    expect(container.querySelectorAll('h1')).toHaveLength(1);
    expect(container.querySelector('h1')?.textContent).toBe(heading);
});
