import { invoke } from '@tauri-apps/api/core';
import type { AppInfo } from './generated/AppInfo';
import type { ReadyReport } from './generated/ReadyReport';

export type { AppInfo, ReadyReport };

export function getAppInfo(): Promise<AppInfo> {
    return invoke<AppInfo>('app_info');
}

export function reportReady(report: ReadyReport): Promise<void> {
    return invoke<void>('report_ready', { report });
}
