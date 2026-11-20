import { invoke } from '@tauri-apps/api/core';
import { listen } from '@tauri-apps/api/event';
import { getCurrentWindow } from '@tauri-apps/api/window';
import type { AppInfo } from './generated/AppInfo';
import type { CertificateChoice } from './generated/CertificateChoice';
import type { Change } from './generated/Change';
import type { IlmPageView } from './generated/IlmPageView';
import type { InventoryView } from './generated/InventoryView';
import type { LocalCertificateView } from './generated/LocalCertificateView';
import type { ProviderChoice } from './generated/ProviderChoice';
import type { Scheme } from './generated/Scheme';
import type { SessionView } from './generated/SessionView';
import type { SettingsView } from './generated/SettingsView';
import type { Shown } from './generated/Shown';

export type { AppInfo, CertificateChoice, Change, LocalCertificateView, ProviderChoice, Scheme, SessionView, SettingsView, Shown };
export type { IlmPageView, InventoryView };
export type { IlmCertificateView } from './generated/IlmCertificateView';
export type { IlmRaProfileView } from './generated/IlmRaProfileView';
export type { InventoryStatus } from './generated/InventoryStatus';
export type { KeyAlgorithm } from './generated/KeyAlgorithm';
export type { KeyLocation } from './generated/KeyLocation';
export type { Use } from './generated/Use';
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

export function setWindowTitle(title: string): Promise<void> {
    return getCurrentWindow().setTitle(title);
}

/** Opens the Settings window; the macOS main window has no Settings page. */
export function openSettings(): Promise<void> {
    return invoke<void>('open_settings');
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

/** The certificates on this computer that can sign in. */
export function certificates(): Promise<CertificateChoice[]> {
    return invoke<CertificateChoice[]>('certificates');
}

/** The certificates of the person on this computer that have a private key here; rejects with the reason they cannot be read. */
export function localCertificates(): Promise<LocalCertificateView[]> {
    return invoke<LocalCertificateView[]>('local_certificates');
}

/** What ILM is known to say about the certificates on this computer; refused while the application is locked. */
export function ilmStatus(): Promise<InventoryView> {
    return invoke<InventoryView>('ilm_status');
}

/** One page of ILM's certificates (1-based), optionally filtered by name. */
export function ilmCertificates(page: number, search: string | null): Promise<IlmPageView> {
    return invoke<IlmPageView>('ilm_certificates', { page, search });
}

/** Checks ILM now and returns the answer. */
export function syncNow(): Promise<InventoryView> {
    return invoke<InventoryView>('sync_now');
}

/** Makes the certificate with this fingerprint the sign-in certificate in ILM. */
export function makeSignInCertificate(fingerprint: string): Promise<InventoryView> {
    return invoke<InventoryView>('make_sign_in_certificate', { fingerprint });
}

/** Calls the handler, without data, each time the inventory or whether a check runs changes; read it with `ilmStatus`. */
export function onInventoryChanged(handler: () => void): Promise<() => void> {
    return listen<null>('inventory-changed', () => handler());
}

/** Resolves when the ILM has answered for the certificate. */
export function signInWithCertificate(fingerprint: string): Promise<SessionView> {
    return invoke<SessionView>('sign_in_with_certificate', { fingerprint });
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

/** Asks the system to confirm the person; resolves to the real view, rejects with the reason it stayed locked. */
export function unlock(): Promise<SessionView> {
    return invoke<SessionView>('unlock');
}

/** Repeats an ended sign-in; the providers to choose from, or none when the browser flow has started. */
export function signInAgain(): Promise<ProviderChoice[]> {
    return invoke<ProviderChoice[]>('sign_in_again');
}

/** Calls the handler with the providers to choose from when the tray started a sign-in again; returns the unlisten. */
export function onSignInChoices(handler: (providers: ProviderChoice[]) => void): Promise<() => void> {
    return listen<ProviderChoice[]>('sign-in-choices', (event) => handler(event.payload));
}

export function windowLabel(): string {
    return getCurrentWindow().label;
}
