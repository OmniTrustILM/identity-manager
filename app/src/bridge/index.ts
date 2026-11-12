import { invoke } from '@tauri-apps/api/core';
import { listen } from '@tauri-apps/api/event';
import { getCurrentWindow } from '@tauri-apps/api/window';
import type { AppInfo } from './generated/AppInfo';
import type { Change } from './generated/Change';
import type { Scheme } from './generated/Scheme';
import type { SettingsView } from './generated/SettingsView';
import type { Shown } from './generated/Shown';

export type { AppInfo, Change, Scheme, SettingsView, Shown };
export type { Entry } from './generated/Entry';
export type { LogLevel } from './generated/LogLevel';
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

export function getSettings(): Promise<SettingsView> {
    return invoke<SettingsView>('settings');
}

export function setSetting(change: Change): Promise<SettingsView> {
    return invoke<SettingsView>('set_setting', { change });
}

/** Calls the handler with the section id each time the shell asks for a section to open; returns the unlisten. */
export function onOpenSection(handler: (section: string) => void): Promise<() => void> {
    return listen<string>('open-section', (event) => handler(event.payload));
}

/** Takes the section the shell was asked to open, if any; it is handed out once. */
export function pendingSection(): Promise<string | null> {
    return invoke<string | null>('pending_section');
}

export function windowLabel(): string {
    return getCurrentWindow().label;
}
