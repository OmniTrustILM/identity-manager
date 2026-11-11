import { clearMocks, mockIPC } from '@tauri-apps/api/mocks';
import { afterEach, describe, expect, it } from 'vitest';
import { getAppInfo, reportReady } from './index';

afterEach(() => clearMocks());

describe('bridge', () => {
    it('getAppInfo calls app_info and returns its answer', async () => {
        const calls: string[] = [];
        mockIPC((command) => {
            calls.push(command);
            return { name: 'Identity Manager', version: '0.1.0' };
        });

        await expect(getAppInfo()).resolves.toEqual({ name: 'Identity Manager', version: '0.1.0' });
        expect(calls).toEqual(['app_info']);
    });

    it('reportReady calls report_ready with the report', async () => {
        const calls: { command: string; args: unknown }[] = [];
        mockIPC((command, args) => {
            calls.push({ command, args });
        });
        const report = { name: 'Identity Manager', version: '0.1.0' };

        await reportReady(report);

        expect(calls).toEqual([{ command: 'report_ready', args: { report } }]);
    });

    it('rejects when the command fails', async () => {
        mockIPC(() => {
            throw new Error('refused');
        });

        await expect(getAppInfo()).rejects.toThrow('refused');
    });
});
