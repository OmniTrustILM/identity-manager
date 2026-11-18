import { invoke } from '@tauri-apps/api/core';
import { listen } from '@tauri-apps/api/event';
import { getCurrentWindow } from '@tauri-apps/api/window';
import type { AppInfo } from './generated/AppInfo';
import type { Change } from './generated/Change';
import type { ProviderChoice } from './generated/ProviderChoice';
import type { Scheme } from './generated/Scheme';
import type { SessionView } from './generated/SessionView';
import type { SettingsView } from './generated/SettingsView';
import type { Shown } from './generated/Shown';

export type { AppInfo, Change, ProviderChoice, Scheme, SessionView, SettingsView, Shown };
export type { PersonView } from './generated/PersonView';
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

export function getSession(): Promise<SessionView> {
    return invoke<SessionView>('session');
}

/** Saves the ILM address and returns the identity providers the person can sign in with. */
export function connect(address: string): Promise<ProviderChoice[]> {
    return invoke<ProviderChoice[]>('connect', { address });
}

/** Resolves when the sign-in in the browser has ended. */
export function signIn(providerId: string): Promise<SessionView> {
    return invoke<SessionView>('sign_in', { providerId });
}

export function reopenBrowser(): Promise<void> {
    return invoke<void>('reopen_browser');
}

export function cancelSignIn(): Promise<void> {
    return invoke<void>('cancel_sign_in');
}

export function signOut(): Promise<SessionView> {
    return invoke<SessionView>('sign_out');
}

/** Calls the handler with the new view each time the session changes; returns the unlisten. */
export function onSessionChanged(handler: (view: SessionView) => void): Promise<() => void> {
    return listen<SessionView>('session-changed', (event) => handler(event.payload));
}

export function windowLabel(): string {
    return getCurrentWindow().label;
}
