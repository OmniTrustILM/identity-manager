import { emit } from '@tauri-apps/api/event';
import { clearMocks, mockIPC, mockWindows } from '@tauri-apps/api/mocks';
import { afterEach, describe, expect, it } from 'vitest';
import {
    colorScheme,
    getAppInfo,
    getSettings,
    hideSummary,
    onOpenSection,
    openMainWindow,
    pendingSection,
    reportReady,
    setSetting,
    windowLabel,
} from './index';

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

    const view = {
        startAtLogin: { value: true, locked: false },
        logLevel: { value: 'info' as const, locked: true },
    };

    it('getSettings calls settings and returns the view', async () => {
        const calls: string[] = [];
        mockIPC((command) => {
            calls.push(command);
            return view;
        });

        await expect(getSettings()).resolves.toEqual(view);
        expect(calls).toEqual(['settings']);
    });

    it('setSetting calls set_setting with the change and returns the view', async () => {
        const calls: { command: string; args: unknown }[] = [];
        mockIPC((command, args) => {
            calls.push({ command, args });
            return view;
        });
        const change = { key: 'startAtLogin' as const, value: false };

        await expect(setSetting(change)).resolves.toEqual(view);
        expect(calls).toEqual([{ command: 'set_setting', args: { change } }]);
    });

    it('onOpenSection passes the section of each open-section event until it is unlistened', async () => {
        mockIPC(() => undefined, { shouldMockEvents: true });
        const sections: string[] = [];

        const unlisten = await onOpenSection((section) => sections.push(section));
        await emit('open-section', 'settings');
        unlisten();
        await emit('open-section', 'other');

        expect(sections).toEqual(['settings']);
    });

    it('pendingSection calls pending_section and returns its answer', async () => {
        const calls: string[] = [];
        mockIPC((command) => {
            calls.push(command);
            return 'settings';
        });

        await expect(pendingSection()).resolves.toBe('settings');
        expect(calls).toEqual(['pending_section']);
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
