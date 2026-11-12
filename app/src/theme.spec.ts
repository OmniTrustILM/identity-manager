import { clearMocks, mockIPC } from '@tauri-apps/api/mocks';
import { emit } from '@tauri-apps/api/event';
import { afterEach, beforeEach, expect, it } from 'vitest';
import type { Scheme } from './bridge';
import { followSystemScheme } from './theme';

const theme = () => document.documentElement.dataset.theme;

function mockScheme(current: Scheme | null) {
    mockIPC((command) => (command === 'color_scheme' ? current : undefined), { shouldMockEvents: true });
}

beforeEach(() => {
    delete document.documentElement.dataset.theme;
});

afterEach(() => clearMocks());

it.each(['dark', 'light'] as const)('sets data-theme to the %s scheme the desktop reports at start', async (scheme) => {
    mockScheme(scheme);

    await followSystemScheme();

    expect(theme()).toBe(scheme);
});

it('leaves data-theme off when the desktop states no preference', async () => {
    mockScheme(null);

    await followSystemScheme();

    expect(theme()).toBeUndefined();
});

it('follows the colour-scheme event and removes data-theme on null', async () => {
    mockScheme('light');
    await followSystemScheme();

    await emit('color-scheme', 'dark');
    expect(theme()).toBe('dark');

    await emit('color-scheme', null);
    expect(theme()).toBeUndefined();
});

it('keeps an event that arrives while the first answer is on its way', async () => {
    mockIPC(
        async (command) => {
            if (command !== 'color_scheme') {
                return undefined;
            }
            await emit('color-scheme', 'dark');
            return 'light';
        },
        { shouldMockEvents: true },
    );

    await followSystemScheme();

    expect(theme()).toBe('dark');
});

it('keeps following the event when the first read fails', async () => {
    mockIPC(
        (command) => {
            if (command === 'color_scheme') {
                throw new Error('no portal');
            }
        },
        { shouldMockEvents: true },
    );

    await followSystemScheme();
    expect(theme()).toBeUndefined();

    await emit('color-scheme', 'dark');
    expect(theme()).toBe('dark');
});

it('stops following once the returned function is called', async () => {
    mockScheme('light');
    const stop = await followSystemScheme();

    stop();
    await emit('color-scheme', 'dark');

    expect(theme()).toBe('light');
});
