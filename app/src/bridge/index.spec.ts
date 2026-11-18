import { emit } from '@tauri-apps/api/event';
import { clearMocks, mockIPC, mockWindows } from '@tauri-apps/api/mocks';
import { afterEach, describe, expect, it } from 'vitest';
import {
    cancelSignIn,
    colorScheme,
    connect,
    getAppInfo,
    getSession,
    getSettings,
    hideSummary,
    onOpenSection,
    onSessionChanged,
    openMainWindow,
    pendingSection,
    reopenBrowser,
    reportReady,
    setSetting,
    signIn,
    signOut,
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

    const signedOut = { state: 'signedOut' as const, address: null, locked: false, problem: null };

    it('getSession calls session and returns the view', async () => {
        const calls: string[] = [];
        mockIPC((command) => {
            calls.push(command);
            return signedOut;
        });

        await expect(getSession()).resolves.toEqual(signedOut);
        expect(calls).toEqual(['session']);
    });

    it('connect passes the address and returns the providers', async () => {
        const calls: [string, unknown][] = [];
        mockIPC((command, args) => {
            calls.push([command, args]);
            return [{ id: '0', name: 'internal' }];
        });

        await expect(connect('ilm.example.com')).resolves.toEqual([{ id: '0', name: 'internal' }]);
        expect(calls).toEqual([['connect', { address: 'ilm.example.com' }]]);
    });

    it('signIn passes the provider id and returns the view', async () => {
        const calls: [string, unknown][] = [];
        mockIPC((command, args) => {
            calls.push([command, args]);
            return signedOut;
        });

        await expect(signIn('0')).resolves.toEqual(signedOut);
        expect(calls).toEqual([['sign_in', { providerId: '0' }]]);
    });

    it('reopenBrowser and cancelSignIn call their commands', async () => {
        const calls: string[] = [];
        mockIPC((command) => {
            calls.push(command);
        });

        await reopenBrowser();
        await cancelSignIn();

        expect(calls).toEqual(['reopen_browser', 'cancel_sign_in']);
    });

    it('signOut calls sign_out and returns the view', async () => {
        const calls: string[] = [];
        mockIPC((command) => {
            calls.push(command);
            return signedOut;
        });

        await expect(signOut()).resolves.toEqual(signedOut);
        expect(calls).toEqual(['sign_out']);
    });

    it('onSessionChanged passes the view of each session-changed event until it is unlistened', async () => {
        mockIPC(() => undefined, { shouldMockEvents: true });
        const views: unknown[] = [];

        const unlisten = await onSessionChanged((view) => views.push(view));
        await emit('session-changed', signedOut);
        unlisten();
        await emit('session-changed', { state: 'starting' });

        expect(views).toEqual([signedOut]);
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
