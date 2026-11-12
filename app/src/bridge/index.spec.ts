import { clearMocks, mockIPC, mockWindows } from '@tauri-apps/api/mocks';
import { afterEach, describe, expect, it } from 'vitest';
import { colorScheme, getAppInfo, hideSummary, openMainWindow, reportReady, windowLabel } from './index';

afterEach(() => clearMocks());

describe('bridge', () => {
    it('getAppInfo calls app_info and returns its answer', async () => {
        const calls: string[] = [];
        mockIPC((command) => {
            calls.push(command);
            return { name: 'Identity Manager', version: '0.1.0', platform: 'macos' as const };
        });

        await expect(getAppInfo()).resolves.toEqual({ name: 'Identity Manager', version: '0.1.0', platform: 'macos' as const });
        expect(calls).toEqual(['app_info']);
    });

    it('reportReady calls report_ready with the report', async () => {
        const calls: { command: string; args: unknown }[] = [];
        mockIPC((command, args) => {
            calls.push({ command, args });
        });
        const report = { name: 'Identity Manager', version: '0.1.0', platform: 'macos' as const };

        await reportReady(report);

        expect(calls).toEqual([{ command: 'report_ready', args: { report } }]);
    });

    it.each([
        ['openMainWindow', openMainWindow, 'open_main_window'],
        ['hideSummary', hideSummary, 'hide_summary'],
    ])('%s calls %s without arguments', async (_name, wrapper, command) => {
        const calls: string[] = [];
        mockIPC((called) => {
            calls.push(called);
        });

        await wrapper();

        expect(calls).toEqual([command]);
    });

    it.each(['dark', 'light', null] as const)('colorScheme calls color_scheme and returns %s', async (scheme) => {
        const calls: string[] = [];
        mockIPC((command) => {
            calls.push(command);
            return scheme;
        });

        await expect(colorScheme()).resolves.toBe(scheme);
        expect(calls).toEqual(['color_scheme']);
    });

    it('windowLabel returns the label of the current window', () => {
        mockWindows('summary');

        expect(windowLabel()).toBe('summary');
    });

    it('rejects when the command fails', async () => {
        mockIPC(() => {
            throw new Error('refused');
        });

        await expect(getAppInfo()).rejects.toThrow('refused');
    });
});
