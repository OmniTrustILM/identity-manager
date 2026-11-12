import { act } from 'react';
import { createRoot, type Root } from 'react-dom/client';
import { afterEach, beforeEach, expect, test } from 'vitest';
import { AppInfoContext, useAppInfo } from '../../app-info';
import type { AppInfo } from '../../bridge';
import { OverviewIcon } from '../../design-system/icons';
import { type Section, sections } from '../../sections';
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
});

async function render(list: Section[], platform: AppInfo['platform'] = 'macos') {
    await act(async () =>
        root.render(
            <AppInfoContext.Provider value={{ ...info, platform }}>
                <Shell sections={list} />
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
