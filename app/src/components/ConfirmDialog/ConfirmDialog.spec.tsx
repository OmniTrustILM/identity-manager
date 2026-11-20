import { act } from 'react';
import { createRoot, type Root } from 'react-dom/client';
import { afterEach, beforeEach, expect, test, vi } from 'vitest';
import { ConfirmDialog } from './ConfirmDialog';

let container: HTMLElement;
let root: Root;
let cancelled: number;

beforeEach(() => {
    (globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true;
    container = document.createElement('div');
    document.body.append(container);
    root = createRoot(container);
    cancelled = 0;
});

afterEach(async () => {
    await act(async () => root.unmount());
    container.remove();
});

const render = (busy: boolean) =>
    act(async () =>
        root.render(
            <ConfirmDialog title="Use it?" confirmLabel="Use" busy={busy} macos onConfirm={vi.fn()} onCancel={() => (cancelled += 1)} />,
        ),
    );
const cancel = () => [...container.querySelectorAll('button')].find((each) => each.textContent === 'Cancel') as HTMLButtonElement;
const pressEscape = () =>
    act(async () => void cancel().dispatchEvent(new KeyboardEvent('keydown', { key: 'Escape', bubbles: true, cancelable: true })));

test('Cancel and Escape withdraw the question', async () => {
    await render(false);
    await pressEscape();
    await act(async () => cancel().click());

    expect(cancelled).toBe(2);
});

test('while the confirmed request runs Cancel is off and Escape does nothing', async () => {
    await render(true);
    await pressEscape();
    await act(async () => cancel().click());

    expect(cancel().disabled).toBe(true);
    expect(cancelled).toBe(0);
});
