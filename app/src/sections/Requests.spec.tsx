import { emit } from '@tauri-apps/api/event';
import { clearMocks, mockIPC } from '@tauri-apps/api/mocks';
import { act } from 'react';
import { createRoot, type Root } from 'react-dom/client';
import { afterEach, beforeEach, expect, test } from 'vitest';
import { inventory } from '../../playwright/ilm';
import { AppInfoContext } from '../app-info';
import type { ApprovalView, InventoryView, MyRequestView, PreparedView } from '../bridge';
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
let decisions: unknown[];
let answer: () => unknown;

beforeEach(() => {
    (globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true;
    container = document.createElement('div');
    document.body.append(container);
    root = createRoot(container);
    current = null;
    calls = [];
    decisions = [];
    answer = () => undefined;
    mockIPC(
        (command, args) => {
            calls.push(command);
            if (command === 'ilm_status') {
                return current;
            }
            if (command === 'decide_approval') {
                decisions.push(args);
                return answer();
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
const change = async (view: InventoryView) => {
    current = view;
    await act(async () => emit('inventory-changed'));
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

const approval = (over: Partial<ApprovalView> = {}): ApprovalView => ({
    uuid: 'a-1',
    action: 'issue',
    requester: 'jnovak',
    requestedAt: new Date(2020, 0, 5, 10, 42).getTime(),
    certificateName: 'S/MIME email',
    raProfileName: 'Corporate S/MIME',
    ...over,
});
const button = (name: string) => container.querySelector(`button[aria-label="${name}"]`) as HTMLButtonElement;
const dialog = () => container.querySelector('dialog') as HTMLDialogElement;
const dialogButton = (label: string) =>
    [...dialog().querySelectorAll('button')].find((each) => each.textContent === label) as HTMLButtonElement;
const alertText = () => container.querySelector('[role="alert"]')?.textContent;
const type = (value: string) =>
    act(async () => {
        const area = dialog().querySelector('textarea') as HTMLTextAreaElement;
        Object.getOwnPropertyDescriptor(HTMLTextAreaElement.prototype, 'value')?.set?.call(area, value);
        area.dispatchEvent(new Event('input', { bubbles: true }));
    });
const click = (element: HTMLElement) => act(async () => element.click());

test('requests waiting for the approval are the first group and the first part of the summary', async () => {
    await render(
        inventory({
            approvals: [approval(), approval({ uuid: 'a-2' })],
            prepared: [prepared('A', null)],
            requests: [waiting('B', 'beingIssued', 1), waiting('C', 'beingIssued', 2)],
        }),
    );

    expect(hasRequests(inventory({ approvals: [approval()] }))).toBe(true);
    expect(groups()).toEqual(['Waiting for your approval', 'Ready for you to issue', 'My requests']);
    expect(container.querySelector('header p')?.textContent).toBe('2 waiting for your approval, 1 ready to issue, 2 in progress');
});

test('an approval shows its name, requester, profile, kind and time, and buttons named after the certificate', async () => {
    await render(inventory({ approvals: [approval(), approval({ uuid: 'a-2', action: 'revoke', certificateName: 'www.example.com' })] }));

    const at = strings.time(approval().requestedAt);
    expect(rows('Waiting for your approval')).toEqual([
        `S/MIME emailFrom jnovak · Corporate S/MIMENew certificate, ${at}Reject…Approve`,
        `www.example.comFrom jnovak · Corporate S/MIMERevocation, ${at}Reject…Approve`,
    ]);
    expect(button('Approve S/MIME email')).not.toBeNull();
    expect(button('Reject S/MIME email')).not.toBeNull();
    expect(container.querySelector('header p')?.textContent).toBe('2 waiting for your approval');
});

test.each([
    ['renew', 'Renewal'],
    ['rekey', 'Rekey'],
])('the kind %s reads %s', async (action, kind) => {
    await render(inventory({ approvals: [approval({ action: action as ApprovalView['action'] })] }));

    expect(text()).toContain(`${kind}, `);
});

test('without a name, a requester and a profile the row says what it can', async () => {
    await render(inventory({ approvals: [approval({ certificateName: null, requester: null, raProfileName: null })] }));

    expect(rows('Waiting for your approval')[0]).toMatch(/^CertificateNew certificate, /);
});

test('without a profile or without a requester the line under the name has the other part', async () => {
    await render(inventory({ approvals: [approval({ raProfileName: null }), approval({ uuid: 'a-2', requester: null })] }));

    expect(rows('Waiting for your approval')[0]).toMatch(/^S\/MIME emailFrom jnovakNew/);
    expect(rows('Waiting for your approval')[1]).toMatch(/^S\/MIME emailCorporate S\/MIMENew/);
});

test('Approve decides at once without a comment, and the buttons are off while it is on its way', async () => {
    let finish: () => void = () => undefined;
    answer = () => new Promise<void>((resolve) => (finish = resolve));
    await render(inventory({ approvals: [approval()] }));

    await click(button('Approve S/MIME email'));

    expect(decisions).toEqual([{ uuid: 'a-1', decision: 'approve', comment: null }]);
    expect(button('Approve S/MIME email').disabled).toBe(true);
    expect(button('Reject S/MIME email').disabled).toBe(true);
    await act(async () => finish());
    expect(button('Approve S/MIME email').disabled).toBe(false);
    expect(alertText()).toBeUndefined();
});

test('Reject… asks first, with the names, and Cancel sends nothing', async () => {
    await render(inventory({ approvals: [approval()] }));

    await click(button('Reject S/MIME email'));

    expect(dialog().open).toBe(true);
    expect(dialog().querySelector('h2')?.textContent).toBe('Reject the request for S/MIME email?');
    expect(dialog().textContent).toContain('jnovak asked for a new certificate in Corporate S/MIME. Rejecting ends the request.');
    expect(dialog().textContent).toContain('Comment (optional)');
    expect(dialog().textContent).toContain('ILM keeps the comment with the approval.');
    await click(dialogButton('Cancel'));
    expect(container.querySelector('dialog')).toBeNull();
    expect(decisions).toEqual([]);
});

test('the question degrades when the requester or the profile is missing', async () => {
    await render(inventory({ approvals: [approval({ requester: null, raProfileName: null, action: 'revoke' })] }));

    await click(button('Reject S/MIME email'));

    expect(dialog().textContent).toContain('Someone asked for a revocation. Rejecting ends the request.');
});

test('Reject sends the comment, and none when it is blank', async () => {
    await render(inventory({ approvals: [approval()] }));

    await click(button('Reject S/MIME email'));
    await type('Use the team certificate.');
    await click(dialogButton('Reject'));
    expect(container.querySelector('dialog')).toBeNull();

    await click(button('Reject S/MIME email'));
    await type('   ');
    await click(dialogButton('Reject'));

    expect(decisions).toEqual([
        { uuid: 'a-1', decision: 'reject', comment: 'Use the team certificate.' },
        { uuid: 'a-1', decision: 'reject', comment: null },
    ]);
});

test.each([
    [{ kind: 'noLongerWaiting' }, 'This request no longer waits for your decision.'],
    [{ kind: 'refused', messages: ['Already decided.', 'Try later.'] }, 'Already decided. Try later.'],
    [{ kind: 'message', message: 'ILM cannot be reached.' }, 'ILM cannot be reached.'],
    [{ kind: 'message', message: '' }, strings.approvalFailed],
    ['plain failure', 'plain failure'],
])('a failed approval shows %j near the group', async (failure, said) => {
    answer = () => Promise.reject(failure);
    await render(inventory({ approvals: [approval()] }));

    await click(button('Approve S/MIME email'));

    expect(alertText()).toBe(said);
    expect(container.querySelector('dialog')).toBeNull();
    expect(button('Approve S/MIME email').disabled).toBe(false);
});

test('a failed rejection is shown in the dialog, which stays open with the comment', async () => {
    answer = () => Promise.reject({ kind: 'noLongerWaiting' });
    await render(inventory({ approvals: [approval()] }));

    await click(button('Reject S/MIME email'));
    await type('No.');
    await click(dialogButton('Reject'));

    expect(dialog().querySelector('[role="alert"]')?.textContent).toBe('This request no longer waits for your decision.');
    expect(container.querySelectorAll('[role="alert"]')).toHaveLength(1);
    expect((dialog().querySelector('textarea') as HTMLTextAreaElement).value).toBe('No.');
});

test('the error of a rejection shows under the group when the request leaves the list with it', async () => {
    answer = () => Promise.reject({ kind: 'noLongerWaiting' });
    await render(inventory({ approvals: [approval()] }));
    await click(button('Reject S/MIME email'));
    await click(dialogButton('Reject'));

    await change(inventory({ approvals: [] }));

    expect(alertText()).toBe('This request no longer waits for your decision.');
    expect(container.querySelector('dialog')).toBeNull();
});

test('the reject dialog closes when its request leaves the list and does not open for the next one', async () => {
    await render(inventory({ approvals: [approval()] }));
    await click(button('Reject S/MIME email'));
    expect(dialog().open).toBe(true);

    await change(inventory({ approvals: [approval({ uuid: 'a-2', certificateName: 'Other' })] }));

    expect(container.querySelector('dialog')).toBeNull();
    expect(button('Reject Other')).not.toBeNull();
});

test('the reject dialog does not open again when its request returns', async () => {
    await render(inventory({ approvals: [approval()] }));
    await click(button('Reject S/MIME email'));

    await change(inventory({ approvals: [] }));
    await change(inventory({ approvals: [approval()] }));

    expect(container.querySelector('dialog')).toBeNull();
    expect(button('Reject S/MIME email')).not.toBeNull();
});

test('the empty state stays only when all three lists are empty', async () => {
    await render(inventory({ approvals: [approval()] }));
    expect(text()).not.toContain('Nothing to issue or follow');
});
