import { invoke } from '@tauri-apps/api/core';
import { getCurrentWindow } from '@tauri-apps/api/window';
import type { AppInfo } from './generated/AppInfo';
import type { Scheme } from './generated/Scheme';
import type { Shown } from './generated/Shown';

export type { AppInfo, Scheme, Shown };
export type { Platform } from './generated/Platform';

export function getAppInfo(): Promise<AppInfo> {
    return invoke<AppInfo>('app_info');
}

export function reportReady(report: Shown): Promise<void> {
    return invoke<void>('report_ready', { report });
}

export function openMainWindow(): Promise<void> {
    return invoke<void>('open_main_window');
}

export function hideSummary(): Promise<void> {
    return invoke<void>('hide_summary');
}

export function colorScheme(): Promise<Scheme | null> {
    return invoke<Scheme | null>('color_scheme');
}

export function windowLabel(): string {
    return getCurrentWindow().label;
}
