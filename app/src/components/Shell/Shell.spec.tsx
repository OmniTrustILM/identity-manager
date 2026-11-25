import { emit } from '@tauri-apps/api/event';
import { clearMocks, mockIPC } from '@tauri-apps/api/mocks';
import { act } from 'react';
import { createRoot, type Root } from 'react-dom/client';
import { afterEach, beforeEach, describe, expect, test, vi } from 'vitest';
import { AppInfoContext, useAppInfo } from '../../app-info';
import type { AppInfo } from '../../bridge';
import { OverviewIcon } from '../../design-system/icons';
import { useNavigation } from '../../navigation';
import { type Section, settingsSection } from '../../sections';
import { strings } from '../../strings';
import { Shell } from './Shell';

/** When set, the registration of the navigate listener resolves only once this is released. */
let registration: Promise<void> | null = null;
/** When set, the registration of the open-section listener resolves only once this is released. */
let sectionRegistration: Promise<void> | null = null;
vi.mock('../../bridge', async (original) => {
    const bridge = await original<typeof import('../../bridge')>();
    return {
        ...bridge,
        onNavigate: (handler: () => void) => {
            const listening = bridge.onNavigate(handler);
            return registration ? listening.then((stop) => registration?.then(() => stop) ?? stop) : listening;
        },
        onOpenSection: (handler: (id: string) => void) => {
            const listening = bridge.onOpenSection(handler);
            return sectionRegistration ? listening.then((stop) => sectionRegistration?.then(() => stop) ?? stop) : listening;
        },
    };
});

const info: AppInfo = { name: 'Identity Manager', version: '0.1.0', platform: 'macos' };
const other: Section = { id: 'other', label: 'Other', icon: OverviewIcon, Component: () => <p>Other content</p> };

const Overview = () => {
    const { showCertificate } = useNavigation();
    return (
        <button type="button" onClick={() => showCertificate('FP:one')}>
            Overview content
        </button>
    );
};
const Certificates = () => <p>Certificates content: {useNavigation().showing?.fingerprint ?? 'none'}</p>;
const sections: Section[] = [
    { id: 'overview', label: strings.overview, icon: OverviewIcon, Component: Overview },
    { id: 'certificates', label: strings.certificates, icon: OverviewIcon, Component: Certificates },
];

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

test('selecting a section shows its content and marks it current', async () => {
    await render([sections[0] as Section, other]);

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

const settingsView = {
    startAtLogin: { value: true, locked: false },
    logLevel: { value: 'info', locked: false },
    requireUnlock: { value: true, locked: false },
    lockAfterIdle: { value: null, locked: false },
    checkEvery: { value: 15, locked: false },
    warnDays: { value: 30, locked: false },
    unlock: 'unsupported',
};
const settingsEntry = () => container.querySelector('nav > div button') as HTMLElement | null;

test.each([
    ['windows', 'Settings'],
    ['linux', 'Preferences'],
] as const)('on %s the sidebar ends with a %s entry that opens the page', async (platform, word) => {
    mockIPC(() => settingsView);

    await render(sections, platform, settingsSection(platform));

    expect(settingsEntry()?.textContent).toBe(word);
    await act(async () => settingsEntry()?.click());
    expect(settingsEntry()?.getAttribute('aria-current')).toBe('page');
    expect(container.querySelector('main h1')?.textContent).toBe(word);
});

test('on macOS the Settings… entry opens the Settings window and stays on the current page', async () => {
    const calls: string[] = [];
    mockIPC((command) => {
        calls.push(command);
    });

    await render(sections, 'macos', settingsSection('macos'));

    expect(settingsEntry()?.textContent).toBe(strings.settingsWindow);
    await act(async () => settingsEntry()?.click());
    expect(calls.filter((command) => command === 'open_settings')).toEqual(['open_settings']);
    expect(settingsEntry()?.getAttribute('aria-current')).toBeNull();
    expect(container.querySelector('nav button')?.getAttribute('aria-current')).toBe('page');
});

test('on macOS a failure to open the Settings window is not thrown', async () => {
    mockIPC(() => {
        throw new Error('refused');
    });

    await render(sections, 'macos', settingsSection('macos'));

    await act(async () => settingsEntry()?.click());
    expect(settingsEntry()?.getAttribute('aria-current')).toBeNull();
});

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

test('a Shell removed before its section listener is registered leaves the request for the next one', async () => {
    mockRequests('settings');
    let release = () => {};
    sectionRegistration = new Promise<void>((resolve) => {
        release = resolve;
    });
    await render(sections, 'windows', settingsSection('windows'));
    await act(async () => root.render(null));

    await act(async () => {
        release();
        await sectionRegistration;
    });
    sectionRegistration = null;
    await render(sections, 'windows', settingsSection('windows'));

    expect(settingsEntry()?.getAttribute('aria-current')).toBe('page');
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
    expect(listens).toEqual(['plugin:event|listen']);

    listens.length = 0;
    await render(sections, 'windows', { ...other, id: 'settings' });
    expect(listens).toEqual(['plugin:event|listen']);

    listens.length = 0;
    await act(async () => root.render(null));
    expect(listens).toEqual(['plugin:event|unlisten', 'plugin:event|unlisten']);
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

test('a banner shows above the section and the section stays usable', async () => {
    await act(async () =>
        root.render(
            <AppInfoContext.Provider value={info}>
                <Shell sections={[other]} banner={<p>Waiting for ILM</p>} />
            </AppInfoContext.Provider>,
        ),
    );

    expect(container.textContent).toContain('Waiting for ILM');
    expect(container.textContent).toContain('Other content');
    expect(container.querySelector('nav')).not.toBeNull();
});

/** The places the main window was asked to show and has not taken yet; `pending_navigation` hands them out one by one. */
const asked: unknown[] = [];
const navigate = (to: unknown) =>
    act(async () => {
        asked.push(to);
        await emit('navigate');
    });
const current = () => container.querySelector('nav [aria-current="page"]')?.textContent;

describe('navigation', () => {
    beforeEach(() => {
        asked.length = 0;
        mockIPC((command) => (command === 'pending_navigation' ? (asked.shift() ?? null) : undefined), {
            shouldMockEvents: true,
        });
    });

    test('a request made before the listener existed shows the certificate at mount and not again later', async () => {
        asked.push({ to: 'certificate', fingerprint: 'FP:one' });
        await render(sections);

        expect(container.querySelector('main')?.textContent).toBe('Certificates content: FP:one');

        await act(async () => (entries()[0] as HTMLElement).click());
        await act(async () => root.render(null));
        await render(sections);

        expect(container.querySelector('main')?.textContent).toBe('Overview content');
    });

    test('a Shell removed before its listener is registered leaves the request for the next one', async () => {
        let release = () => {};
        registration = new Promise<void>((resolve) => {
            release = resolve;
        });
        await render(sections);
        await act(async () => root.render(null));
        asked.push({ to: 'certificate', fingerprint: 'FP:one' });

        await act(async () => {
            release();
            await registration;
        });
        registration = null;
        await render(sections);

        expect(container.querySelector('main')?.textContent).toBe('Certificates content: FP:one');
    });

    test('a request for a certificate opens Certificates with that certificate, again for the same one', async () => {
        await render(sections);

        await navigate({ to: 'certificate', fingerprint: 'FP:one' });
        expect(current()).toBe(strings.certificates);
        expect(container.querySelector('main')?.textContent).toBe('Certificates content: FP:one');

        await act(async () => (entries()[0] as HTMLElement).click());
        expect(container.querySelector('main')?.textContent).toBe('Overview content');
        await act(async () => (entries()[1] as HTMLElement).click());
        expect(container.querySelector('main')?.textContent).toBe('Certificates content: none');

        await navigate({ to: 'certificate', fingerprint: 'FP:one' });
        expect(container.querySelector('main')?.textContent).toBe('Certificates content: FP:one');
    });

    test('a request for the overview opens it from Certificates', async () => {
        await render(sections);
        await navigate({ to: 'certificate', fingerprint: 'FP:one' });

        await navigate({ to: 'overview' });

        expect(current()).toBe(strings.overview);
        expect(container.querySelector('main')?.textContent).toBe('Overview content');
    });

    test('a section can ask for a certificate to be shown', async () => {
        await render(sections);

        await act(async () => (container.querySelector('main button') as HTMLElement).click());

        expect(container.querySelector('main')?.textContent).toBe('Certificates content: FP:one');
    });

    test('requests for sections that are not shown are ignored', async () => {
        await render([other]);

        await navigate({ to: 'certificate', fingerprint: 'FP:one' });
        await navigate({ to: 'overview' });

        expect(container.querySelector('main')?.textContent).toBe('Other content');
    });
});

test('a section that leaves the list while open stays shown and in the sidebar until another is selected', async () => {
    const lasting = [sections[0] as Section, other];
    await render(lasting);
    await act(async () => (entries()[1] as HTMLElement).click());

    await render([sections[0] as Section]);

    expect(container.querySelector('main')?.textContent).toBe('Other content');
    expect(entries().map((entry) => entry.textContent)).toEqual([strings.overview, 'Other']);
    expect(entries().map((entry) => entry.getAttribute('aria-current'))).toEqual([null, 'page']);

    await act(async () => (entries()[0] as HTMLElement).click());

    expect(entries().map((entry) => entry.textContent)).toEqual([strings.overview]);
    expect(container.querySelector('main')?.textContent).toBe('Overview content');
});

test('a section that leaves the list while it is not open is gone at once', async () => {
    await render([sections[0] as Section, other]);

    await render([sections[0] as Section]);

    expect(entries().map((entry) => entry.textContent)).toEqual([strings.overview]);
});
