import { clearMocks, mockIPC } from '@tauri-apps/api/mocks';
import { act } from 'react';
import { createRoot, type Root } from 'react-dom/client';
import { afterEach, beforeEach, expect, test, vi } from 'vitest';
import { ilmCertificate, inventory, page } from '../../playwright/ilm';
import type { IlmPageView, InventoryView } from '../bridge';
import { strings } from '../strings';
import { IlmCertificates } from './IlmCertificates';

const now = new Date(2026, 5, 21, 10, 0, 0).getTime();

let container: HTMLElement;
let root: Root;
let asked: { page: number; search: string | null }[];
let totals: (number | null)[];

beforeEach(() => {
    (globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true;
    vi.useFakeTimers({ toFake: ['Date', 'setTimeout', 'clearTimeout'] });
    vi.setSystemTime(now);
    container = document.createElement('div');
    document.body.append(container);
    root = createRoot(container);
    asked = [];
    totals = [];
});

afterEach(async () => {
    await act(async () => root.unmount());
    container.remove();
    clearMocks();
    vi.useRealTimers();
});

function answer(handler: (args: { page: number; search: string | null }) => Promise<IlmPageView> | IlmPageView) {
    mockIPC((command, args) => {
        if (command === 'ilm_certificates') {
            const request = args as { page: number; search: string | null };
            asked.push(request);
            return handler(request);
        }
        return undefined;
    });
}

const onTotal = (total: number | null) => totals.push(total);
const draw = (current: InventoryView = inventory(), system: 'macos' | 'windows' = 'macos', local: string[] = []) => (
    <IlmCertificates inventory={current} local={new Set(local)} system={system} onTotal={onTotal} />
);
const render = (...parts: Parameters<typeof draw>) => act(async () => root.render(draw(...parts)));

const options = () => [...container.querySelectorAll<HTMLElement>('[role="option"]')];
const detail = () => container.querySelector('section') as HTMLElement;
const search = () => container.querySelector('input') as HTMLInputElement;
const button = (name: string) => [...container.querySelectorAll('button')].find((candidate) => candidate.textContent === name);
const advance = (ms: number) => act(async () => vi.advanceTimersByTimeAsync(ms));
const type = (value: string) =>
    act(async () => {
        const setter = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value')?.set;
        setter?.call(search(), value);
        search().dispatchEvent(new Event('input', { bubbles: true }));
    });
const key = (target: Element, name: string) =>
    act(async () => void target.dispatchEvent(new KeyboardEvent('keydown', { key: name, bubbles: true, cancelable: true })));

const twoPages = (number: number) => page([ilmCertificate(`Cert ${number}`)], { pageNumber: number, totalPages: 3, totalItems: 121 });

test('shows the first page with name, issuer, state and expiry and reports the total', async () => {
    answer(() =>
        page(
            [
                ilmCertificate('api-gateway', { issuerName: 'Demo Server Sub CA', state: 'pending_approval' }),
                ilmCertificate('old', { notAfter: now - 3 * 86_400_000 }),
                ilmCertificate('no-dates', { notBefore: null, notAfter: null, issuerName: null, fingerprint: null }),
            ],
            { totalItems: 161_193, totalPages: 3224 },
        ),
    );
    await render();

    expect(asked).toEqual([{ page: 1, search: null }]);
    expect(options().map((option) => option.getAttribute('aria-label'))).toEqual([
        'api-gateway, Demo Server Sub CA, Pending approval, Expires in 212 days',
        expect.stringMatching(/^old, Demo Client Sub CA, Issued, Expired /),
        'no-dates, Issued',
    ]);
    expect(options()[1]?.querySelector('.text-bad')?.textContent).toContain('Expired');
    expect(totals.at(-1)).toBe(161_193);
    expect(container.textContent).toContain(strings.pageRange(1, 3, 161_193));
    expect(container.querySelector('[role="listbox"]')?.getAttribute('aria-label')).toBe('Certificates in ILM');
});

test('a new check of ILM asks for the shown page again', async () => {
    answer(() => twoPages(1));
    await render(inventory({ checkedAt: now }));
    expect(asked).toEqual([{ page: 1, search: null }]);

    await render(inventory({ checkedAt: now + 60_000 }));

    expect(asked).toEqual([
        { page: 1, search: null },
        { page: 1, search: null },
    ]);
});

test('marks the certificates that are on this computer and the archived ones', async () => {
    answer(() => page([ilmCertificate('mine'), ilmCertificate('theirs', { archived: true })]));
    await render(inventory(), 'macos', ['IL:mine']);

    expect(options()[0]?.getAttribute('aria-label')).toContain('On this Mac');
    expect(options()[0]?.querySelector('[role="img"]')?.getAttribute('title')).toBe('On this Mac');
    expect(options()[1]?.getAttribute('aria-label')).toContain('Archived');
    expect(options()[1]?.textContent).toContain('Archived');
    expect(options()[1]?.querySelector('[role="img"]')).toBeNull();
});

test('says PC on Windows', async () => {
    answer(() => page([ilmCertificate('mine')]));
    await render(inventory(), 'windows', ['IL:mine']);

    expect(options()[0]?.querySelector('[role="img"]')?.getAttribute('aria-label')).toBe('On this PC');
});

test('the detail has the Certificate, In ILM and Fingerprint groups and no buttons', async () => {
    answer(() =>
        page([
            ilmCertificate('A', { raProfile: { uuid: 'r', name: 'Client certificates' }, groups: ['Engineering', 'VPN users'] }),
            ilmCertificate('B', { owner: null, issuerName: null, serial: null, notBefore: null, notAfter: null, fingerprint: null }),
        ]),
    );
    await render();

    expect(detail().querySelector('h2')?.textContent).toBe('A');
    expect(detail().textContent).toContain('CertificateValid from');
    expect(detail().textContent).toContain(
        'In ILMStateIssuedValidationValidRA ProfileClient certificatesOwneralex.morganGroupsEngineering, VPN users',
    );
    expect(detail().textContent).toContain('Fingerprint (SHA-256)IL:A');
    expect(detail().querySelector('button')).toBeNull();
    await act(async () => options()[1]?.click());
    expect(detail().textContent).toContain('RA ProfileNot managed');
    expect(detail().textContent).not.toContain('Owner');
    expect(detail().textContent).not.toContain('Fingerprint');
});

test('colours the validation of a failed certificate', async () => {
    answer(() => page([ilmCertificate('A', { validationStatus: 'failed' }), ilmCertificate('B', { validationStatus: 'inactive' })]));
    await render();

    expect(detail().querySelector('.text-bad')?.textContent).toBe('Failed');
    await act(async () => options()[1]?.click());
    expect(detail().querySelector('.text-bad')).toBeNull();
});

test('Previous and Next move through the pages and say where the person is', async () => {
    answer(({ page: number }) => twoPages(number));
    await render();

    expect(container.textContent).toContain('1–1 of 121');
    expect(button('Previous')?.disabled).toBe(true);
    await act(async () => button('Next')?.click());
    expect(asked.at(-1)).toEqual({ page: 2, search: null });
    expect(container.textContent).toContain('51–51 of 121');
    await act(async () => button('Next')?.click());
    expect(button('Next')?.disabled).toBe(true);
    await act(async () => button('Previous')?.click());
    expect(asked.at(-1)).toEqual({ page: 2, search: null });
});

test('the search runs on Enter at once and starts again at the first page', async () => {
    answer(({ page: number, search: text }) =>
        page([ilmCertificate(text ?? `Cert ${number}`)], { pageNumber: number, totalPages: 3, totalItems: 121 }),
    );
    await render();
    await act(async () => button('Next')?.click());

    await type('  gateway ');
    await key(search(), 'Enter');

    expect(asked.at(-1)).toEqual({ page: 1, search: 'gateway' });
    await advance(1000);
    expect(asked).toHaveLength(3);
    await key(search(), 'Enter');
    expect(asked).toHaveLength(3);
});

test('the search runs after a 400 ms pause and only once for quick typing', async () => {
    answer(() => page([ilmCertificate('A')]));
    await render();

    await type('g');
    await advance(300);
    await type('ga');
    await advance(300);
    expect(asked).toHaveLength(1);
    await advance(100);

    expect(asked).toEqual([
        { page: 1, search: null },
        { page: 1, search: 'ga' },
    ]);
});

test('clearing the search lists everything again', async () => {
    answer(() => page([ilmCertificate('A')]));
    await render();
    await type('ga');
    await advance(400);
    await type('');
    await advance(400);

    expect(asked.at(-1)).toEqual({ page: 1, search: null });
});

test('an answer to an older request is dropped', async () => {
    let release: (answer: IlmPageView) => void = () => undefined;
    const slow = new Promise<IlmPageView>((resolve) => {
        release = resolve;
    });
    const replies = [slow, Promise.resolve(page([ilmCertificate('Newer')]))];
    answer(() => replies.shift() as Promise<IlmPageView>);
    await render();
    await type('n');
    await key(search(), 'Enter');
    expect(options().map((option) => option.getAttribute('aria-label')?.split(',')[0])).toEqual(['Newer']);

    await act(async () => release(page([ilmCertificate('Older')])));

    expect(options().map((option) => option.getAttribute('aria-label')?.split(',')[0])).toEqual(['Newer']);
});

test('an empty answer says nothing was found', async () => {
    answer(() => page([]));
    await render();

    expect(container.textContent).toContain(strings.noIlmCertificates);
    expect(container.querySelector('[role="listbox"]')).toBeNull();
});

test.each([
    ['ILM does not allow this.', 'ILM does not allow this.'],
    ['', strings.ilmLoadFailed],
])('an error (%j) shows a message and Try again asks again', async (reason, shown) => {
    let fail = true;
    answer(() => (fail ? Promise.reject(reason) : page([ilmCertificate('A')])));
    await render();

    expect(container.querySelector('[role="alert"]')?.textContent).toContain(shown);
    expect(container.textContent).not.toContain(strings.noIlmCertificates);
    fail = false;
    await act(async () => button('Try again')?.click());

    expect(asked).toHaveLength(2);
    expect(container.querySelector('[role="alert"]')).toBeNull();
    expect(options()).toHaveLength(1);
});

test('a failing page keeps the page that was shown and offers Try again', async () => {
    const replies = [() => twoPages(1), () => Promise.reject('Slow.')];
    answer(() => replies.shift()?.() as IlmPageView);
    await render();
    await act(async () => button('Next')?.click());

    expect(container.querySelector('[role="alert"]')?.textContent).toContain('Slow.');
    expect(options()).toHaveLength(1);
});

test('offline shows the first page that was kept, with a note, and search and paging are off', async () => {
    answer(() => page([ilmCertificate('Online')]));
    const kept = page([ilmCertificate('Kept')], { totalItems: 90, totalPages: 2 });
    await render(inventory({ status: { state: 'offline', since: now - 60_000, reason: 'down' }, firstPage: kept }));

    expect(asked).toEqual([]);
    expect(container.textContent).toContain(strings.ilmOffline(now - 60_000));
    expect(options().map((option) => option.getAttribute('aria-label')?.split(',')[0])).toEqual(['Kept']);
    expect(search().disabled).toBe(true);
    expect(button('Previous')?.disabled).toBe(true);
    expect(button('Next')?.disabled).toBe(true);
    expect(totals.at(-1)).toBe(90);
});

test('offline without a kept page says nothing was found, and without a time says only what needs ILM', async () => {
    answer(() => page([]));
    await render(inventory({ status: { state: 'offline', since: null, reason: 'down' }, firstPage: null }));

    expect(container.textContent).toContain('Search and paging need ILM.');
    expect(container.textContent).not.toContain('Showing the first page');
    expect(container.textContent).toContain(strings.noIlmCertificates);
});

test('when ILM comes back the page is read again, and a change of status does not read it again by itself', async () => {
    answer(() => page([ilmCertificate('Live')]));
    await render(inventory({ status: { state: 'offline', since: null, reason: 'down' }, firstPage: null }));
    expect(asked).toHaveLength(0);

    await render(inventory());
    expect(asked).toHaveLength(1);
    await render(inventory({ checking: true }));
    expect(asked).toHaveLength(1);
});

test('arrows, Home and End move the selection and the focus; there is one tab stop', async () => {
    answer(() => page([ilmCertificate('A'), ilmCertificate('B'), ilmCertificate('C')]));
    await render();
    expect(options().map((option) => option.tabIndex)).toEqual([0, -1, -1]);
    options()[0]?.focus();

    await key(document.activeElement as Element, 'ArrowDown');
    expect(document.activeElement).toBe(options()[1]);
    expect(detail().querySelector('h2')?.textContent).toBe('B');
    await key(document.activeElement as Element, 'End');
    expect(options()[2]?.getAttribute('aria-selected')).toBe('true');
    await key(document.activeElement as Element, 'Home');
    expect(options()[0]?.getAttribute('aria-selected')).toBe('true');
    await key(document.activeElement as Element, 'x');
    expect(options()[0]?.getAttribute('aria-selected')).toBe('true');
});

test('leaving the view drops a pending search', async () => {
    answer(() => page([ilmCertificate('A')]));
    await render();
    await type('g');
    await act(async () => root.unmount());
    await advance(1000);

    expect(asked).toHaveLength(1);
    root = createRoot(container);
});
