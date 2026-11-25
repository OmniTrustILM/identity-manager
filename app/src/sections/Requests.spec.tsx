import { clearMocks, mockIPC } from '@tauri-apps/api/mocks';
import { act } from 'react';
import { createRoot, type Root } from 'react-dom/client';
import { afterEach, beforeEach, expect, test } from 'vitest';
import { inventory } from '../../playwright/ilm';
import { AppInfoContext } from '../app-info';
import type { InventoryView, MyRequestView, PreparedView } from '../bridge';
import { strings } from '../strings';
import { hasRequests, Requests, standing } from './Requests';

const day = 24 * 60 * 60 * 1000;
const hour = 60 * 60 * 1000;

const prepared = (name: string, registration: PreparedView['registration'], over: Partial<PreparedView> = {}): PreparedView => ({
    uuid: `uuid-${name}`,
    name,
    raProfile: { uuid: 'ra-1', name: 'Corporate VPN' },
    registration,
    subject: [],
    ...over,
});
const waiting = (label: string, state: MyRequestView['state'], since: number): MyRequestView => ({ uuid: null, label, since, state });

let container: HTMLElement;
let root: Root;
let current: InventoryView | null;
let calls: string[];

beforeEach(() => {
    (globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true;
    container = document.createElement('div');
    document.body.append(container);
    root = createRoot(container);
    current = null;
    calls = [];
    mockIPC(
        (command) => {
            calls.push(command);
            if (command === 'ilm_status') {
                return current;
            }
        },
        { shouldMockEvents: true },
    );
});

afterEach(async () => {
    await act(async () => root.unmount());
    container.remove();
    clearMocks();
});

const render = async (view: InventoryView | null) => {
    current = view;
    await act(async () =>
        root.render(
            <AppInfoContext.Provider value={{ name: 'Identity Manager', version: '0.1.0', platform: 'macos' }}>
                <Requests />
            </AppInfoContext.Provider>,
        ),
    );
    await act(async () => new Promise((resolve) => setTimeout(resolve, 20)));
};
const text = () => container.textContent ?? '';
const groups = () => [...container.querySelectorAll('h2')].map((heading) => heading.textContent);
const rows = (group: string) => {
    const heading = [...container.querySelectorAll('h2')].find((candidate) => candidate.textContent === group);
    return [...(heading?.parentElement?.querySelectorAll('li') ?? [])].map((row) => row.textContent);
};

test('the section is wanted when the inventory has prepared certificates or requests', () => {
    expect(hasRequests(null)).toBe(false);
    expect(hasRequests(inventory())).toBe(false);
    expect(hasRequests(inventory({ prepared: [prepared('A', null)] }))).toBe(true);
    expect(hasRequests(inventory({ requests: [waiting('B', 'beingIssued', 1)] }))).toBe(true);
});

test('the days to issue are rounded up and a window that has closed is over', () => {
    const now = 1_000_000_000;
    const days = (expiresAt: number | null, state = 'active') => standing(prepared('A', { state, expiresAt }), now);

    expect(days(now + 1)).toEqual({ kind: 'ready', days: 1 });
    expect(days(now + day)).toEqual({ kind: 'ready', days: 1 });
    expect(days(now + day + 1)).toEqual({ kind: 'ready', days: 2 });
    expect(days(now + 6 * day - hour)).toEqual({ kind: 'ready', days: 6 });
    expect(days(now)).toEqual({ kind: 'ended' });
    expect(days(now - day)).toEqual({ kind: 'ended' });
    expect(days(null)).toEqual({ kind: 'ready', days: null });
    expect(standing(prepared('A', null), now)).toEqual({ kind: 'ready', days: null });
    expect(days(now - day, 'expired')).toEqual({ kind: 'ended' });
    expect(days(now + day, 'expired')).toEqual({ kind: 'ended' });
    expect(days(now + day, 'locked')).toEqual({ kind: 'locked' });
    expect(days(now - day, 'closed')).toEqual({ kind: 'ended' });
    expect(days(now + 2 * day, 'other')).toEqual({ kind: 'ready', days: 2 });
});

test('the page lists what is ready and what is in progress, with the counts in the subtitle', async () => {
    const since = new Date(2020, 0, 5, 9, 12).getTime();
    await render(
        inventory({
            prepared: [
                prepared('VPN gateway access', { state: 'active', expiresAt: Date.now() + 5 * day + hour }),
                prepared(
                    'Wi-Fi laptop',
                    { state: 'expired', expiresAt: Date.now() - day },
                    { raProfile: { uuid: 'r', name: 'Corporate Wi-Fi' } },
                ),
                prepared('Remote desktop', { state: 'locked', expiresAt: null }),
                prepared('No registration', null),
            ],
            requests: [waiting('S/MIME email', 'pendingApproval', since), waiting('Developer signing', 'beingIssued', Date.now())],
        }),
    );

    expect(container.querySelector('h1')?.textContent).toBe('Requests');
    expect(text()).toContain('2 ready to issue, 2 in progress');
    expect(groups()).toEqual(['Ready for you to issue', 'My requests']);
    expect(rows('Ready for you to issue')).toEqual([
        'VPN gateway accessCorporate VPNIssue within 6 daysIssue…',
        'Wi-Fi laptopCorporate Wi-FiIssue window endedAsk your administrator',
        'Remote desktopCorporate VPNLocked after too many attemptsAsk your administrator',
        'No registrationCorporate VPNIssue…',
    ]);
    expect(rows('My requests')[0]).toBe(`S/MIME emailRequested ${strings.time(since)}Waiting for approval`);
    expect(rows('My requests')[1]).toContain('Being issued');
    expect([...container.querySelectorAll('button')].map((button) => button.getAttribute('aria-label'))).toEqual([
        'Issue VPN gateway access',
        'Issue No registration',
    ]);
});

test.each([
    [1, 'Issue within 1 day'],
    [3, 'Issue within 3 days'],
])('a registration with %i days left says "%s"', async (left, said) => {
    await render(inventory({ prepared: [prepared('A', { state: 'active', expiresAt: Date.now() + left * day - hour })] }));

    expect(text()).toContain(said);
});

test('a page with only prepared certificates leaves out the requests and omits a count of zero', async () => {
    await render(inventory({ prepared: [prepared('A', null)] }));
    expect(groups()).toEqual(['Ready for you to issue']);
    expect(text()).toContain('1 ready to issue');
    expect(text()).not.toContain('in progress');
});

test('a page with only requests leaves out the group of prepared certificates', async () => {
    await render(inventory({ requests: [waiting('B', 'beingIssued', Date.now())] }));
    expect(groups()).toEqual(['My requests']);
    expect(container.querySelector('header p')?.textContent).toBe('1 in progress');
});

test('prepared certificates that cannot be issued are not counted as ready', async () => {
    await render(inventory({ prepared: [prepared('A', { state: 'locked', expiresAt: null })] }));

    expect(container.querySelector('header p')).toBeNull();
    expect(groups()).toEqual(['Ready for you to issue']);
});

test('with nothing to show the page says so', async () => {
    await render(inventory());

    expect(groups()).toEqual(['Nothing to issue or follow']);
    expect(text()).toContain('Certificates your administrator prepares for you and the requests you send appear here.');
});

test('before the inventory is read nothing is claimed', async () => {
    await render(null);

    expect(groups()).toEqual([]);
});

test('Issue… opens the sheet for that certificate and Cancel closes it', async () => {
    mockIPC(
        (command) => {
            if (command === 'ilm_status') {
                return current;
            }
            return command === 'open_prepared_forms' ? { request: null, issue: null, custom: null } : undefined;
        },
        { shouldMockEvents: true },
    );
    await render(inventory({ prepared: [prepared('VPN gateway access', null)] }));

    await act(async () => (container.querySelector('button[aria-label="Issue VPN gateway access"]') as HTMLButtonElement).click());
    expect(container.querySelector('dialog h2')?.textContent).toBe('Issue VPN gateway access');

    await act(async () =>
        ([...container.querySelectorAll('dialog button')].find((b) => b.textContent === 'Cancel') as HTMLElement).click(),
    );
    expect(container.querySelector('dialog')).toBeNull();
});
