import { clearMocks, mockIPC } from '@tauri-apps/api/mocks';
import { act } from 'react';
import { createRoot, type Root } from 'react-dom/client';
import { afterEach, beforeEach, expect, test, vi } from 'vitest';
import type { FollowView } from './bridge';
import { RenewStatus, useRenewNow } from './renewNow';
import { strings } from './strings';

let container: HTMLElement;
let root: Root;
let commands: string[];
let answers: FollowView[];

function Probe() {
    const { progress, renew } = useRenewNow();
    return (
        <>
            <button type="button" onClick={() => renew('FP:one')}>
                go
            </button>
            <RenewStatus progress={progress} />
        </>
    );
}

beforeEach(async () => {
    (globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true;
    vi.useFakeTimers({ toFake: ['setTimeout', 'clearTimeout'] });
    container = document.createElement('div');
    document.body.append(container);
    root = createRoot(container);
    commands = [];
    answers = [
        { state: 'waiting', stage: 'beingIssued' },
        { state: 'installed', storage: 'keychain', validUntil: 0 },
    ];
    mockIPC((command) => {
        commands.push(command);
        if (command === 'renew_now') {
            return { certificate: 'new', label: 'x' };
        }
        if (command === 'follow_request') {
            return answers.length > 1 ? answers.shift() : answers[0];
        }
    });
    await act(async () => root.render(<Probe />));
});

afterEach(async () => {
    await act(async () => root.unmount());
    container.remove();
    clearMocks();
    vi.useRealTimers();
});

const go = () => act(async () => container.querySelector('button')?.click());

test('a renewal is followed every two seconds until it is installed', async () => {
    await go();
    expect(container.querySelector('output')?.textContent).toBe(strings.renewalInProgress);

    await act(async () => vi.advanceTimersByTimeAsync(2000));

    expect(container.querySelector('output')?.textContent).toBe(strings.renewalDone);
    await act(async () => vi.advanceTimersByTimeAsync(10000));
    expect(commands.filter((command) => command === 'follow_request')).toHaveLength(2);
});

test('following stops after thirty answers that are not final', async () => {
    answers = [{ state: 'waiting', stage: 'beingIssued' }];
    await go();

    await act(async () => vi.advanceTimersByTimeAsync(2000 * 40));

    expect(commands.filter((command) => command === 'follow_request')).toHaveLength(30);
});

test('the renewal is no longer followed or shown as under way once the polling gives up', async () => {
    answers = [{ state: 'waiting', stage: 'beingIssued' }];
    mockIPC((command, payload) => {
        commands.push(command === 'stop_following_request' ? `stop:${(payload as { certificate: string }).certificate}` : command);
        if (command === 'renew_now') {
            return { certificate: 'new', label: 'x' };
        }
        if (command === 'follow_request') {
            return answers[0];
        }
    });
    await go();

    await act(async () => vi.advanceTimersByTimeAsync(2000 * 40));

    expect(commands.filter((command) => command.startsWith('stop'))).toEqual(['stop:new']);
    expect(container.querySelector('output')).toBeNull();
});

test('a read that fails is tried again', async () => {
    let failed = false;
    mockIPC((command) => {
        commands.push(command);
        if (command === 'renew_now') {
            return { certificate: 'new', label: 'x' };
        }
        if (command === 'follow_request') {
            if (!failed) {
                failed = true;
                return Promise.reject('down');
            }
            return { state: 'installed', storage: 'keychain', validUntil: 0 };
        }
    });
    await go();
    expect(container.querySelector('output')).toBeNull();

    await act(async () => vi.advanceTimersByTimeAsync(2000));

    expect(container.querySelector('output')?.textContent).toBe(strings.renewalDone);
});

test('leaving the screen stops following and tells the app', async () => {
    await go();

    await act(async () => root.unmount());
    await act(async () => vi.advanceTimersByTimeAsync(10000));

    expect(commands.filter((command) => command === 'follow_request')).toHaveLength(1);
    expect(commands).toContain('stop_following_request');
    root = createRoot(container);
});

test('a renewal that is accepted after the screen is gone is released at once', async () => {
    let accept: (value: unknown) => void = () => undefined;
    mockIPC((command) => {
        commands.push(command);
        if (command === 'renew_now') {
            return new Promise((resolve) => {
                accept = resolve;
            });
        }
    });
    await go();
    await act(async () => root.unmount());

    await act(async () => accept({ certificate: 'late', label: 'x' }));

    expect(commands).toEqual(['renew_now', 'stop_following_request']);
    root = createRoot(container);
});
