import { act } from 'react';
import { createRoot, type Root } from 'react-dom/client';
import { afterEach, beforeEach, expect, test } from 'vitest';
import { strings } from '../../strings';
import { LockNote } from './LockNote';
import { Select } from './Select';
import { Switch } from './Switch';

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

test('the switch is a checkbox with the switch role that reports the new state', async () => {
    const changes: boolean[] = [];
    await act(async () => root.render(<Switch aria-label="Name" checked={false} onChange={(checked) => changes.push(checked)} />));
    const input = container.querySelector('input') as HTMLInputElement;

    await act(async () => input.click());

    expect(input.type).toBe('checkbox');
    expect(input.getAttribute('role')).toBe('switch');
    expect(input.getAttribute('aria-label')).toBe('Name');
    expect(changes).toEqual([true]);
});

test.each([
    [true, strings.switchOn],
    [false, strings.switchOff],
])('the state word for checked=%s is %s and hidden from assistive technology', async (checked, word) => {
    await act(async () => root.render(<Switch aria-label="Name" checked={checked} onChange={() => undefined} />));

    const state = container.querySelector('[aria-hidden]');

    expect(state?.textContent).toBe(word);
    expect(container.querySelector('input')?.checked).toBe(checked);
});

test('a disabled switch cannot be operated', async () => {
    const changes: boolean[] = [];
    await act(async () => root.render(<Switch aria-label="Name" disabled checked onChange={(checked) => changes.push(checked)} />));

    await act(async () => (container.querySelector('input') as HTMLInputElement).click());

    expect(changes).toEqual([]);
});

test('the select offers the options and reports the chosen one', async () => {
    const chosen: string[] = [];
    await act(async () =>
        root.render(<Select aria-label="Level" value="a" options={['a', 'b']} onChange={(value) => chosen.push(value)} />),
    );
    const select = container.querySelector('select') as HTMLSelectElement;

    await act(async () => {
        select.value = 'b';
        select.dispatchEvent(new Event('change', { bubbles: true }));
    });

    expect([...select.options].map((option) => option.textContent)).toEqual(['a', 'b']);
    expect(select.getAttribute('aria-label')).toBe('Level');
    expect(chosen).toEqual(['b']);
});

test('the lock note says why and carries the id the control points at', async () => {
    await act(async () => root.render(<LockNote id="note" />));

    expect(document.getElementById('note')?.textContent).toBe(strings.managedByOrganization);
    expect(container.querySelector('svg')?.getAttribute('aria-hidden')).toBe('true');
});
