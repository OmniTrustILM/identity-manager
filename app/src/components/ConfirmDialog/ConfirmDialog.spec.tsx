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
const dialog = () => container.querySelector('dialog') as HTMLDialogElement;
const pressEscape = () => act(async () => void dialog().dispatchEvent(new Event('cancel', { bubbles: false, cancelable: true })));

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

test('Escape is taken over from the browser, which would close the dialog by itself', async () => {
    await render(false);
    const event = new Event('cancel', { cancelable: true });
    await act(async () => void dialog().dispatchEvent(event));

    expect(event.defaultPrevented).toBe(true);
});

test('the dialog is modal and the confirming button has the focus', async () => {
    await render(false);

    expect(dialog().open).toBe(true);
    expect(document.activeElement?.textContent).toBe('Use');
});

test('while busy the focus stays in the dialog', async () => {
    await render(false);
    await render(true);

    expect(document.activeElement).toBe(dialog());
});
