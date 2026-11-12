import { act } from 'react';
import { createRoot, type Root } from 'react-dom/client';
import { afterEach, beforeEach, expect, test } from 'vitest';
import { OverviewIcon } from '../../design-system/icons';
import type { Section } from '../../sections';
import { strings } from '../../strings';
import { Sidebar } from './Sidebar';

const Empty = () => null;
const sections: Section[] = ['one', 'two', 'three'].map((id) => ({ id, label: id, icon: OverviewIcon, Component: Empty }));

let container: HTMLElement;
let root: Root;
let selected: string[];

beforeEach(() => {
    (globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true;
    container = document.createElement('div');
    document.body.append(container);
    root = createRoot(container);
    selected = [];
});

afterEach(async () => {
    await act(async () => root.unmount());
    container.remove();
});

const bottom: Section = { id: 'settings', label: 'Settings', icon: OverviewIcon, Component: Empty };

async function render(title?: string, withBottom = false) {
    await act(async () =>
        root.render(
            <Sidebar
                sections={sections}
                bottom={withBottom ? bottom : undefined}
                current="two"
                onSelect={(id) => selected.push(id)}
                title={title}
            />,
        ),
    );
}

const buttons = () => [...container.querySelectorAll('button')];

async function press(key: string) {
    await act(async () => {
        document.activeElement?.dispatchEvent(new KeyboardEvent('keydown', { key, bubbles: true, cancelable: true }));
    });
}

test('is a named navigation with one button per section, the current one marked', async () => {
    await render();

    expect(container.querySelector('nav')?.getAttribute('aria-label')).toBe(strings.navigation);
    expect(buttons().map((button) => button.textContent)).toEqual(['one', 'two', 'three']);
    expect(buttons().map((button) => button.getAttribute('aria-current'))).toEqual([null, 'page', null]);
});

test('reports the section a button opens', async () => {
    await render();

    await act(async () => buttons()[2]?.click());

    expect(selected).toEqual(['three']);
});

test('puts only the current entry in the tab order', async () => {
    await render();

    expect(buttons().map((button) => button.tabIndex)).toEqual([-1, 0, -1]);
});

test('moves focus with the arrow keys, Home and End, and stays within the list', async () => {
    await render();
    await act(async () => buttons()[1]?.focus());

    await press('ArrowDown');
    expect(document.activeElement).toBe(buttons()[2]);
    await press('ArrowDown');
    expect(document.activeElement).toBe(buttons()[2]);
    await press('Home');
    expect(document.activeElement).toBe(buttons()[0]);
    await press('ArrowUp');
    expect(document.activeElement).toBe(buttons()[0]);
    await press('End');
    expect(document.activeElement).toBe(buttons()[2]);
    expect(buttons().map((button) => button.tabIndex)).toEqual([-1, -1, 0]);
});

test('ignores other keys', async () => {
    await render();
    await act(async () => buttons()[1]?.focus());

    await press('a');

    expect(document.activeElement).toBe(buttons()[1]);
});

test('shows the title only when given one', async () => {
    await render('Identity Manager');
    expect(container.querySelector('nav')?.textContent).toContain('Identity Manager');

    await render();
    expect(container.querySelector('nav')?.textContent).not.toContain('Identity Manager');
});

test('the bottom entry sits apart from the sections and is selected like them', async () => {
    await render(undefined, true);

    const apart = container.querySelector('nav > div');
    expect(apart?.querySelectorAll('button')).toHaveLength(1);
    expect(apart?.textContent).toBe('Settings');
    expect([...container.querySelectorAll('nav > button')].map((button) => button.textContent)).toEqual(['one', 'two', 'three']);

    await act(async () => (container.querySelector('nav > div button') as HTMLElement).click());

    expect(selected).toEqual(['settings']);
});

test('the arrow keys reach the bottom entry and End and Home span all entries', async () => {
    await render(undefined, true);
    await act(async () => buttons()[2]?.focus());

    await press('ArrowDown');
    expect(document.activeElement).toBe(buttons()[3]);
    await press('Home');
    expect(document.activeElement).toBe(buttons()[0]);
    await press('End');
    expect(document.activeElement).toBe(buttons()[3]);
    expect(buttons().map((button) => button.tabIndex)).toEqual([-1, -1, -1, 0]);
});

test('without a bottom entry nothing is set apart', async () => {
    await render();

    expect(container.querySelector('nav > div')).toBeNull();
});
