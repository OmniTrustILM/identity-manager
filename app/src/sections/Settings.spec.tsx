import { emit } from '@tauri-apps/api/event';
import { clearMocks, mockIPC, mockWindows } from '@tauri-apps/api/mocks';
import { act } from 'react';
import { createRoot, type Root } from 'react-dom/client';
import { afterEach, beforeEach, expect, test } from 'vitest';
import { AppInfoContext } from '../app-info';
import type { AppInfo, Change, SessionView, SettingsView } from '../bridge';
import { strings } from '../strings';
import { Settings } from './Settings';

const open: SettingsView = {
    startAtLogin: { value: true, locked: false },
    logLevel: { value: 'info', locked: false },
    ilmUrl: { value: null, locked: false },
    requireUnlock: { value: true, locked: false },
    lockAfterIdle: { value: null, locked: false },
    unlock: 'available',
};
const lockedLevel: SettingsView = {
    ...open,
    logLevel: { value: 'debug', locked: true },
};

let container: HTMLElement;
let root: Root;
let calls: { command: string; args: unknown }[];

beforeEach(() => {
    (globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true;
    container = document.createElement('div');
    document.body.append(container);
    root = createRoot(container);
    calls = [];
    localStorage.clear();
});

afterEach(async () => {
    await act(async () => root.unmount());
    container.remove();
    clearMocks();
});

type Handler = (command: string, args: unknown) => unknown;

function bridge(handler: Handler) {
    mockWindows('settings');
    mockIPC(
        (command, args) => {
            calls.push({ command, args });
            return handler(command, args);
        },
        { shouldMockEvents: true },
    );
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

/** Opens a pane of the macOS Settings window by its tab. */
async function openPane(title: string) {
    const tab = [...container.querySelectorAll('[role="tab"]')].find((candidate) => candidate.textContent === title) as HTMLElement;
    await act(async () => tab.click());
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
    expect(calls.map((call) => call.command).sort()).toEqual(['plugin:window|set_title', 'session', 'settings']);
    expect(calls.find((call) => call.command === 'plugin:window|set_title')?.args).toMatchObject({ value: strings.general });
});

test('changing the switch sends the change and shows the view that comes back', async () => {
    bridge((command) => (command === 'set_setting' ? { ...open, startAtLogin: { value: false, locked: false } } : open));
    await render();

    await act(async () => toggle().click());

    expect(calls.at(-1)).toEqual({
        command: 'set_setting',
        args: {
            change: { key: 'startAtLogin', value: false } satisfies Change,
        },
    });
    expect(toggle().checked).toBe(false);
});

test('changing the select sends the level', async () => {
    bridge((command, args) =>
        command === 'set_setting'
            ? {
                  ...open,
                  logLevel: {
                      value: (args as { change: { value: 'warn' } }).change.value,
                      locked: false,
                  },
              }
            : open,
    );
    await render();

    await chooseLevel('warn');

    expect(calls.at(-1)).toEqual({
        command: 'set_setting',
        args: { change: { key: 'logLevel', value: 'warn' } },
    });
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
        if (command !== 'settings') {
            return signedOut;
        }
        reloads += 1;
        return reloads === 1 ? open : Promise.reject('gone');
    });
    await render();

    await act(async () => toggle().click());

    expect(alerts()).toEqual(['no']);
    expect(toggle().checked).toBe(true);
});

test('a reload on focus that answers after a change does not bring back the old value', async () => {
    let answerReload: (view: SettingsView) => void = () => undefined;
    let reads = 0;
    bridge((command) => {
        if (command === 'set_setting') {
            return { ...open, startAtLogin: { value: false, locked: false } };
        }
        if (command !== 'settings') {
            return signedOut;
        }
        reads += 1;
        return reads === 1 ? open : new Promise((resolve) => (answerReload = resolve));
    });
    await render();

    await act(async () => {
        window.dispatchEvent(new Event('focus'));
    });
    await act(async () => toggle().click());
    await act(async () => answerReload(open));

    expect(toggle().checked).toBe(false);
});

test('a second click before the first change is answered switches back', async () => {
    const answers: ((view: SettingsView) => void)[] = [];
    bridge((command) => (command === 'set_setting' ? new Promise((resolve) => answers.push(resolve)) : open));
    await render();

    await act(async () => toggle().click());
    expect(toggle().checked).toBe(false);
    await act(async () => toggle().click());

    expect(calls.filter((call) => call.command === 'set_setting').map((call) => call.args)).toEqual([
        { change: { key: 'startAtLogin', value: false } },
        { change: { key: 'startAtLogin', value: true } },
    ]);
    await act(async () =>
        answers[0]?.({
            ...open,
            startAtLogin: { value: false, locked: false },
        }),
    );
    expect(toggle().checked).toBe(true);
    await act(async () => answers[1]?.(open));
    expect(toggle().checked).toBe(true);
});

function deferredChanges() {
    const answers: {
        resolve: (view: SettingsView) => void;
        reject: (reason: string) => void;
    }[] = [];
    bridge((command) => (command === 'set_setting' ? new Promise((resolve, reject) => answers.push({ resolve, reject })) : open));
    return answers;
}

test('a refusal of an older change after a newer one succeeded changes nothing', async () => {
    const answers = deferredChanges();
    await render();
    await act(async () => toggle().click());
    await act(async () => toggle().click());

    await act(async () => answers[1]?.resolve(open));
    await act(async () => answers[0]?.reject('no'));

    expect(toggle().checked).toBe(true);
    expect(alerts()).toEqual([]);
    expect(calls.filter((call) => call.command === 'settings')).toHaveLength(1);
});

test('a success of an older change does not clear the error of a newer one', async () => {
    const answers = deferredChanges();
    await render();
    await act(async () => toggle().click());
    await act(async () => toggle().click());

    await act(async () => answers[1]?.reject('no'));
    await act(async () =>
        answers[0]?.resolve({
            ...open,
            startAtLogin: { value: false, locked: false },
        }),
    );

    expect(alerts()).toEqual(['no']);
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

const signedIn: Extract<SessionView, { state: 'signedIn' }> = {
    state: 'signedIn',
    address: 'https://ilm.example.com',
    person: { name: 'Alex Morgan', username: 'alex.morgan' },
    allowedListings: [],
    certificate: null,
    unreachable: false,
};
const signedOut: SessionView = {
    state: 'signedOut',
    address: null,
    locked: false,
    problem: null,
    again: false,
};

function connected(settings: SettingsView = open, session: SessionView = signedIn, connect: () => unknown = () => []) {
    bridge((command) => {
        switch (command) {
            case 'settings':
                return settings;
            case 'session':
                return session;
            case 'connect':
                return connect();
            default:
                return signedOut;
        }
    });
}

const address = () => container.querySelector('input[type="text"]') as HTMLInputElement;
const signOutButton = () => [...container.querySelectorAll('button')].find((button) => button.textContent === strings.signOut);

async function typeAddress(text: string) {
    await act(async () => {
        Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value')?.set?.call(address(), text);
        address().dispatchEvent(new Event('input', { bubbles: true }));
    });
}

test('signed in, the group Connection shows the address, the person and Sign out', async () => {
    connected();

    await render('windows');

    const groups = [...container.querySelectorAll('section')];
    expect(groups.map((group) => group.querySelector('h2')?.textContent)).toEqual([strings.general, strings.security, strings.connection]);
    expect(groups[2]?.getAttribute('aria-labelledby')).toBe(groups[2]?.querySelector('h2')?.id);
    expect(container.querySelector(`label[for="${address().id}"]`)?.textContent).toBe(strings.ilmAddress);
    expect(address().value).toBe('https://ilm.example.com');
    expect(address().disabled).toBe(false);
    expect(container.textContent).toContain('Alex Morgan');
    expect(container.textContent).toContain('alex.morgan');
    expect(signOutButton()).toBeDefined();
});

test('signed in with a certificate, the account row says so and shows the short fingerprint', async () => {
    connected(open, { ...signedIn, certificate: '3F:A2:9C:01' });

    await render('windows');

    expect(container.textContent).toContain(strings.signedInWithCertificate);
    expect(container.textContent).toContain('3F:A2:9C:01');
    expect(container.textContent).not.toContain('alex.morgan');
    expect(signOutButton()).toBeDefined();
});

test('without a sign-in there is no group Connection', async () => {
    connected(open, signedOut);

    await render('windows');

    expect(container.querySelectorAll('section')).toHaveLength(2);
    expect(container.textContent).not.toContain(strings.signOut);
});

test('an address set by the organization is locked and says so', async () => {
    connected({
        ...open,
        ilmUrl: { value: 'https://ilm.example.com', locked: true },
        requireUnlock: { value: true, locked: false },
        lockAfterIdle: { value: null, locked: false },
    });

    await render('linux');

    expect(address().disabled).toBe(true);
    expect(document.getElementById(address().getAttribute('aria-describedby') ?? '')?.textContent).toBe(strings.managedByOrganization);
});

test('in the Settings window on macOS the address can only be read', async () => {
    connected();

    await render('macos');
    await openPane(strings.connection);

    expect(address().readOnly).toBe(true);
    expect(address().value).toBe('https://ilm.example.com');
    expect(signOutButton()).toBeDefined();
});

test('confirming a new address with Enter connects to it', async () => {
    connected();
    await render('windows');
    await typeAddress('ilm.example.org');

    await act(async () => {
        address().dispatchEvent(new KeyboardEvent('keydown', { key: 'Enter', bubbles: true }));
    });

    expect(calls.filter((call) => call.command === 'connect')).toEqual([{ command: 'connect', args: { address: 'ilm.example.org' } }]);
});

test('leaving the field with a new address connects to it, with the same address it does nothing', async () => {
    connected();
    await render('windows');

    await act(async () => address().dispatchEvent(new FocusEvent('focusout', { bubbles: true })));
    expect(calls.some((call) => call.command === 'connect')).toBe(false);

    await typeAddress('ilm.example.org');
    await act(async () => address().dispatchEvent(new FocusEvent('focusout', { bubbles: true })));
    expect(calls.filter((call) => call.command === 'connect')).toHaveLength(1);
});

test('a refused address shows the reason under the row and brings back the address in use', async () => {
    connected(open, signedIn, () => Promise.reject('The address must start with https://'));
    await render('windows');
    await typeAddress('http://ilm.example.org');

    await act(async () => address().dispatchEvent(new FocusEvent('focusout', { bubbles: true })));

    expect(alerts()).toEqual(['The address must start with https://']);
    expect(address().value).toBe('https://ilm.example.com');
    expect(address().getAttribute('aria-describedby')).toContain(document.querySelector('[role="alert"]')?.id);
});

test('a refusal without a message says that the setting could not be changed', async () => {
    connected(open, signedIn, () => Promise.reject(''));
    await render('windows');
    await typeAddress('ilm.example.org');

    await act(async () => address().dispatchEvent(new FocusEvent('focusout', { bubbles: true })));

    expect(alerts()).toEqual([strings.settingFailed]);
});

test('Sign out asks the session to sign out', async () => {
    connected();
    await render('windows');

    await act(async () => signOutButton()?.click());

    expect(calls.at(-1)).toEqual({ command: 'sign_out', args: {} });
});

test('the group follows the session: it goes when the person signs out and shows the new address after a change', async () => {
    connected();
    await render('windows');

    await act(async () =>
        emit('session-changed', {
            ...signedIn,
            address: 'https://ilm.example.org',
        }),
    );
    expect(address().value).toBe('https://ilm.example.org');

    await act(async () => emit('session-changed', signedOut));
    expect(container.querySelectorAll('section')).toHaveLength(2);
});

const security = () =>
    [...container.querySelectorAll('section')].find((group) => group.querySelector('h2')?.textContent === strings.security);
const field = (label: string) => {
    const row = [...(security()?.querySelectorAll('label') ?? [])].find((candidate) => candidate.textContent === label);
    return document.getElementById(row?.htmlFor ?? '');
};
const unlockSwitch = (label = strings.unlockWithTouchId) => field(label) as HTMLInputElement;
const idle = () => field(strings.lockAfterIdle) as HTMLSelectElement;
const optionTexts = () => [...idle().options].map((option) => option.textContent);

test('on macOS the group Security has the switch for Touch ID and the select for inactivity', async () => {
    bridge(() => open);

    await render('macos');
    await openPane(strings.security);

    expect(unlockSwitch().checked).toBe(true);
    expect(unlockSwitch().disabled).toBe(false);
    expect(optionTexts()).toEqual([strings.never, '5 minutes', '15 minutes', '30 minutes', '60 minutes']);
    expect(idle().value).toBe('never');
    expect(idle().disabled).toBe(false);
    expect(security()?.getAttribute('aria-labelledby')).toBe(security()?.querySelector('h2')?.id);
});

test('on Windows the switch asks for Windows Hello', async () => {
    bridge(() => open);

    await render('windows');

    expect(unlockSwitch(strings.unlockWithHello)).toBeDefined();
    expect(container.textContent).not.toContain(strings.unlockWithTouchId);
});

test('the group Security is not shown where the system cannot unlock', async () => {
    bridge(() => ({ ...open, unlock: 'unsupported' }));

    await render('linux');

    expect(security()).toBeUndefined();
});

test('turning the switch off and choosing a time send the changes', async () => {
    bridge((command, args) => {
        if (command !== 'set_setting') {
            return open;
        }
        const { key, value } = (args as { change: Change }).change;
        return { ...open, [key]: { value, locked: false } };
    });
    await render('macos');
    await openPane(strings.security);

    await act(async () => unlockSwitch().click());
    expect(calls.at(-1)?.args).toEqual({ change: { key: 'requireUnlock', value: false } });
    expect(idle().disabled).toBe(true);

    await act(async () => unlockSwitch().click());
    await act(async () => {
        idle().value = '15';
        idle().dispatchEvent(new Event('change', { bubbles: true }));
    });
    expect(calls.at(-1)?.args).toEqual({ change: { key: 'lockAfterIdle', value: 15 } });
    expect(idle().value).toBe('15');

    await act(async () => {
        idle().value = 'never';
        idle().dispatchEvent(new Event('change', { bubbles: true }));
    });
    expect(calls.at(-1)?.args).toEqual({ change: { key: 'lockAfterIdle', value: null } });
});

test('the time cannot be chosen while the switch is off', async () => {
    bridge(() => ({ ...open, requireUnlock: { value: false, locked: false }, lockAfterIdle: { value: 15, locked: false } }));

    await render('macos');
    await openPane(strings.security);

    expect(unlockSwitch().checked).toBe(false);
    expect(idle().disabled).toBe(true);
    expect(idle().value).toBe('15');
});

test('rows set by the organization are locked and say so', async () => {
    bridge(() => ({ ...open, requireUnlock: { value: false, locked: true }, lockAfterIdle: { value: 15, locked: true } }));

    await render('macos');
    await openPane(strings.security);

    expect(unlockSwitch().disabled).toBe(true);
    expect(idle().disabled).toBe(true);
    expect(security()?.textContent?.split(strings.managedByOrganization)).toHaveLength(3);
    expect(unlockSwitch().getAttribute('aria-describedby')).not.toBeNull();
});

test('a time of the organization that is not in the list is shown in minutes and stays locked', async () => {
    bridge(() => ({ ...open, lockAfterIdle: { value: 7, locked: true } }));

    await render('windows');

    expect(optionTexts()).toContain('7 minutes');
    expect(idle().value).toBe('7');
    expect(idle().disabled).toBe(true);
});

test('where Windows Hello is not set up both rows are off and disabled, with the way to set it up', async () => {
    bridge(() => ({ ...open, unlock: 'notSetUp' }));

    await render('windows');

    expect(unlockSwitch(strings.unlockWithHello).checked).toBe(false);
    expect(unlockSwitch(strings.unlockWithHello).disabled).toBe(true);
    expect(idle().disabled).toBe(true);
    expect(security()?.textContent).toContain(strings.setUpHello);
    expect(unlockSwitch(strings.unlockWithHello).getAttribute('aria-describedby')).not.toBeNull();
});

test('where the Mac has no password both rows are disabled, with the way to set one', async () => {
    bridge(() => ({ ...open, unlock: 'notSetUp' }));

    await render('macos');
    await openPane(strings.security);

    expect(unlockSwitch().disabled).toBe(true);
    expect(security()?.textContent).toContain(strings.setUpPassword);
});

test('a refused change of the switch shows the reason on its row', async () => {
    bridge((command) => (command === 'set_setting' ? Promise.reject('Not allowed.') : open));
    await render('macos');
    await openPane(strings.security);

    await act(async () => unlockSwitch().click());

    expect(alerts()).toEqual(['Not allowed.']);
});

test('while the application is locked the window shows Unlock, not the settings', async () => {
    connected(open, { state: 'locked' });

    await render('macos');

    expect(container.querySelector('h1')?.textContent).toBe(strings.lockedTitle);
    expect(container.querySelector('section')).toBeNull();
    expect(container.textContent).not.toContain(strings.startAtLogin);
});

test('Settings returns when the session is unlocked', async () => {
    connected(open, { state: 'locked' });
    await render('macos');

    await act(async () => emit('session-changed', signedIn));
    await openPane(strings.security);

    expect(security()).toBeDefined();
});

test('Settings does not ask to unlock by itself', async () => {
    connected(open, { state: 'locked' });

    await render('macos');

    expect(calls.map((call) => call.command)).not.toContain('unlock');
});
