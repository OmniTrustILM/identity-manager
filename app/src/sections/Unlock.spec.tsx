import { clearMocks, mockIPC } from '@tauri-apps/api/mocks';
import { act } from 'react';
import { createRoot, type Root } from 'react-dom/client';
import { afterEach, beforeEach, expect, test, vi } from 'vitest';
import { strings } from '../strings';
import { Unlock } from './Unlock';

let container: HTMLElement;
let root: Root;
let asked: number;
let answer: () => Promise<unknown>;

beforeEach(() => {
    (globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true;
    container = document.createElement('div');
    document.body.append(container);
    root = createRoot(container);
    asked = 0;
    answer = () => Promise.reject('Unlock was cancelled.');
    mockIPC((command) => {
        if (command === 'unlock') {
            asked++;
            return answer();
        }
    });
});

afterEach(async () => {
    await act(async () => root.unmount());
    container.remove();
    clearMocks();
    vi.restoreAllMocks();
});

const render = (automatic: boolean) => act(async () => root.render(<Unlock automatic={automatic} />));
const button = () => container.querySelector('button') as HTMLButtonElement;
const problem = () => container.querySelector('[role="alert"]')?.textContent;
const visibility = (state: 'hidden' | 'visible') =>
    act(async () => {
        vi.spyOn(document, 'visibilityState', 'get').mockReturnValue(state);
        document.dispatchEvent(new Event('visibilitychange'));
    });

test('says the application is locked and offers Unlock, focused', async () => {
    await render(false);

    expect(container.querySelector('h1')?.textContent).toBe(strings.lockedTitle);
    expect(button().textContent).toBe(strings.unlock);
    expect(document.activeElement).toBe(button());
    expect(problem()).toBeUndefined();
});

test('without automatic it asks only when the button is pressed', async () => {
    await render(false);
    expect(asked).toBe(0);

    await act(async () => button().click());

    expect(asked).toBe(1);
});

test('with automatic it asks once as it opens and the refusal is shown under the button', async () => {
    await render(true);

    expect(asked).toBe(1);
    expect(problem()).toBe('Unlock was cancelled.');
});

test('it does not ask again on a render or a focus, which also follows the closing of the system prompt', async () => {
    await render(true);

    await render(true);
    await act(async () => {
        window.dispatchEvent(new Event('focus'));
    });

    expect(asked).toBe(1);
});

test('it asks again each time the window is shown, not when it is hidden', async () => {
    await render(true);

    await visibility('hidden');
    expect(asked).toBe(1);

    await visibility('visible');
    expect(asked).toBe(2);
});

test('a window shown while a prompt is open waits for that prompt', async () => {
    let finish: () => void = () => undefined;
    answer = () => new Promise((resolve) => (finish = () => resolve(undefined)));
    await render(true);

    await visibility('visible');
    expect(asked).toBe(1);
    expect(button().getAttribute('aria-busy')).toBe('true');

    await act(async () => finish());
    expect(button().getAttribute('aria-busy')).toBe('false');
});

test('after a refusal the button asks again and clears the problem while it waits', async () => {
    await render(false);
    await act(async () => button().click());
    expect(problem()).toBe('Unlock was cancelled.');

    answer = () => Promise.reject('Touch ID is not available.');
    await act(async () => button().click());

    expect(asked).toBe(2);
    expect(problem()).toBe('Touch ID is not available.');
});

test('a refusal without a reason says it could not unlock', async () => {
    answer = () => Promise.reject('');
    await render(false);

    await act(async () => button().click());

    expect(problem()).toBe(strings.unlockFailed);
});

test('stops listening once it is gone', async () => {
    await render(true);
    await act(async () => root.render(null));

    await visibility('visible');

    expect(asked).toBe(1);
});
