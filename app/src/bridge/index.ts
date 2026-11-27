import { invoke } from '@tauri-apps/api/core';
import { listen } from '@tauri-apps/api/event';
import { getCurrentWindow } from '@tauri-apps/api/window';
import type { AddChoicesView } from './generated/AddChoicesView';
import type { AddResultView } from './generated/AddResultView';
import type { AppInfo } from './generated/AppInfo';
import type { AttributeCallbackResult } from './generated/AttributeCallbackResult';
import type { AttributeCheck } from './generated/AttributeCheck';
import type { AttributeFieldProblem } from './generated/AttributeFieldProblem';
import type { AttributeValue } from './generated/AttributeValue';
import type { FollowView } from './generated/FollowView';
import type { SubjectPart } from './generated/SubjectPart';
import type { KeyTypeId } from './generated/KeyTypeId';
import type { RaProfileChoice } from './generated/RaProfileChoice';
import type { ApprovalDecision } from './generated/ApprovalDecision';
import type { ApprovalFailure } from './generated/ApprovalFailure';
import type { RequestedView } from './generated/RequestedView';
import type { RevokeReason } from './generated/RevokeReason';
import type { RequestFailure } from './generated/RequestFailure';
import type { RequestFormsView } from './generated/RequestFormsView';
import type { RequestOffers } from './generated/RequestOffers';
import type { StorageId } from './generated/StorageId';
import type { FormProblems } from './generated/FormProblems';
import type { CertificateChoice } from './generated/CertificateChoice';
import type { Change } from './generated/Change';
import type { IlmPageView } from './generated/IlmPageView';
import type { IlmTarget } from './generated/IlmTarget';
import type { InventoryView } from './generated/InventoryView';
import type { LocalCertificateView } from './generated/LocalCertificateView';
import type { Navigation } from './generated/Navigation';
import type { ProviderChoice } from './generated/ProviderChoice';
import type { Scheme } from './generated/Scheme';
import type { SessionView } from './generated/SessionView';
import type { SettingsView } from './generated/SettingsView';
import type { Shown } from './generated/Shown';
import type { SummaryView } from './generated/SummaryView';

export type { AppInfo, CertificateChoice, Change, LocalCertificateView, ProviderChoice, Scheme, SessionView, SettingsView, Shown };
export type { IlmPageView, InventoryView, SubjectPart };
export type { MyRequestView } from './generated/MyRequestView';
export type { ApprovalAction } from './generated/ApprovalAction';
export type { ApprovalDecision } from './generated/ApprovalDecision';
export type { ApprovalFailure } from './generated/ApprovalFailure';
export type { ApprovalView } from './generated/ApprovalView';
export type { PreparedView } from './generated/PreparedView';
export type { RegistrationView } from './generated/RegistrationView';
export type { SubjectKind } from './generated/SubjectKind';
export type { AddChoicesView, AddResultView, Navigation, SummaryView };
export type { AttributeCallbackResult, AttributeCheck, AttributeFieldProblem, AttributeValue, FormProblems, IlmTarget };
export type { EndedReason } from './generated/EndedReason';
export type { FollowView } from './generated/FollowView';
export type { KeyTypeId } from './generated/KeyTypeId';
export type { NotInstalledCause } from './generated/NotInstalledCause';
export type { RequestedView } from './generated/RequestedView';
export type { RevokeReason } from './generated/RevokeReason';
export type { RevokingStage } from './generated/RevokingStage';
export type { RenewalView } from './generated/RenewalView';
export type { AutomaticRenewal } from './generated/AutomaticRenewal';
export type { RequestFailure } from './generated/RequestFailure';
export type { RequestFormsView } from './generated/RequestFormsView';
export type { RequestOffers } from './generated/RequestOffers';
export type { StorageId } from './generated/StorageId';
export type { StorageOffer } from './generated/StorageOffer';
export type { WaitingStage } from './generated/WaitingStage';
export type { AttributeFieldKind } from './generated/AttributeFieldKind';
export type { AttributeFieldView } from './generated/AttributeFieldView';
export type { AttributeFormView } from './generated/AttributeFormView';
export type { AttributeOptionView } from './generated/AttributeOptionView';
export type { GroupChoice } from './generated/GroupChoice';
export type { RaProfileChoice } from './generated/RaProfileChoice';
export type { AskedProfile } from './generated/AskedProfile';
export type { AttentionItemView } from './generated/AttentionItemView';
export type { SummaryCounts } from './generated/SummaryCounts';
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

/** Shows the main window; `target` is "overview" or the fingerprint of a certificate, which the main window is then asked to show. */
export function openMainWindow(target?: string): Promise<void> {
    return invoke<void>('open_main_window', { target: target ?? null });
}

/** Calls the handler each time another window opens the main window with something to show; returns the unlisten. */
export function onNavigate(handler: () => void): Promise<() => void> {
    return listen('navigate', () => handler());
}

/** Takes what the main window was asked to show, if anything; it is handed out once. */
export function pendingNavigation(): Promise<Navigation | null> {
    return invoke<Navigation | null>('pending_navigation');
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

/** How the certificates on this computer stand, or null while nobody is signed in; refused while the application is locked. */
export function overview(): Promise<SummaryView | null> {
    return invoke<SummaryView | null>('overview');
}

/** The groups and RA Profiles the person may choose from, each null when ILM does not let them list it. */
export function addToIlmChoices(): Promise<AddChoicesView> {
    return invoke<AddChoicesView>('add_to_ilm_choices');
}

/** The values of a form by attribute name, as the person typed them. */
export type FormValues = Record<string, AttributeValue>;

/** The open form of an add and the values the person gave. */
export interface AddForm {
    id: string;
    values: FormValues;
}

/** Adds the certificates of this computer with these fingerprints to ILM, with the form if there is one, and returns how each ended. Rejects with `FormProblems` when the form has problems; nothing is sent then. */
export function addToIlm(
    fingerprints: string[],
    group: string | null,
    raProfile: string | null,
    form: AddForm | null,
): Promise<AddResultView[]> {
    return invoke<AddResultView[]>('add_to_ilm', { fingerprints, group, raProfile, form });
}

/** The problems a rejected `addToIlm` carries, or null when it was refused for another reason. */
export function formProblems(error: unknown): AttributeFieldProblem[] | null {
    return typeof error === 'object' && error !== null && 'problems' in error ? (error as FormProblems).problems : null;
}

/** Runs the callback of a field of an open form for the values given; `seq` numbers the runs of the field. The result carries the form as it is afterwards. */
export function attributeCallback(id: string, field: string, values: FormValues, seq: number): Promise<AttributeCallbackResult> {
    return invoke<AttributeCallbackResult>('attribute_callback', { id, field, values, seq });
}

/** The problem of every field of an open form that has one, for the values given, and the revision of the form they were checked against. */
export function checkAttributes(id: string, values: FormValues): Promise<AttributeCheck> {
    return invoke<AttributeCheck>('check_attributes', { id, values });
}

/** The RA Profiles the person may request a certificate from. */
export function requestChoices(): Promise<RaProfileChoice[]> {
    return invoke<RaProfileChoice[]>('request_choices');
}

/** Opens the three forms of a request for an RA Profile; each is closed with `closeForm`. */
export function openRequestForms(raProfile: string): Promise<RequestFormsView> {
    return invoke<RequestFormsView>('open_request_forms', { raProfile });
}

/** Opens the forms of a certificate prepared in advance, without the request form; each is closed with `closeForm`. */
export function openPreparedForms(uuid: string): Promise<RequestFormsView> {
    return invoke<RequestFormsView>('open_prepared_forms', { uuid });
}

/** The key storages and key types this computer and the organization allow for a new key. */
export function requestOffers(): Promise<RequestOffers> {
    return invoke<RequestOffers>('request_offers');
}

/** The forms of a request as filled in, by kind; a kind without a form is left out. */
export type RequestForms = Partial<Record<'request' | 'issue' | 'custom', AddForm>>;

/** Creates a key, sends the signed request to ILM and returns the certificate to follow; rejects with a `RequestFailure`. `asked` says the organization's policy asked for it. */
export function requestCertificate(
    raProfile: string,
    forms: RequestForms,
    storage: StorageId,
    keyType: KeyTypeId,
    asked?: boolean,
): Promise<RequestedView> {
    return invoke<RequestedView>('request_certificate', { raProfile, forms, storage, keyType, asked });
}

/**
 * Completes a certificate prepared in advance with a new key and returns the certificate to follow; rejects with a
 * `RequestFailure`, also when ILM no longer registers the reviewed `subject`. The challenge, when ILM asks for one,
 * goes to ILM and nowhere else.
 */
export function completeCertificate(
    uuid: string,
    forms: RequestForms,
    storage: StorageId,
    keyType: KeyTypeId,
    challenge: string | null,
    subject: SubjectPart[],
): Promise<RequestedView> {
    return invoke<RequestedView>('complete_certificate', { uuid, forms, storage, keyType, challenge, subject });
}

/** Renews the certificate with this fingerprint now and returns the renewal to follow; rejects with a `RequestFailure`. */
export function renewNow(fingerprint: string): Promise<RequestedView> {
    return invoke<RequestedView>('renew_now', { fingerprint });
}

/** Revokes the certificate with this fingerprint and returns the revocation to follow; rejects with a `RequestFailure`. */
export function revokeCertificate(fingerprint: string, reason: RevokeReason, remove: boolean): Promise<RequestedView> {
    return invoke<RequestedView>('revoke_certificate', { fingerprint, reason, remove });
}

/** Switches the automatic renewal of the certificate with this fingerprint on or off. */
export function setRenewalSwitch(fingerprint: string, on: boolean): Promise<InventoryView> {
    return invoke<InventoryView>('set_renewal_switch', { fingerprint, on });
}

/** How the request that made this certificate stands. */
export function followRequest(certificate: string): Promise<FollowView> {
    return invoke<FollowView>('follow_request', { certificate });
}

/** The wizard no longer shows this request, so the app tells the person by a notification how it ends. */
export function stopFollowingRequest(certificate: string): Promise<void> {
    return invoke<void>('stop_following_request', { certificate });
}

/** Approves or rejects a request waiting for the person; rejects with an `ApprovalFailure`. The comment goes to ILM only. */
export function decideApproval(uuid: string, decision: ApprovalDecision, comment: string | null): Promise<void> {
    return invoke<void>('decide_approval', { uuid, decision, comment });
}

/** What a rejected `decideApproval` carries; anything else it was rejected with becomes a message. */
export function approvalFailure(error: unknown): ApprovalFailure {
    if (typeof error === 'object' && error !== null && 'kind' in error) {
        return error as ApprovalFailure;
    }
    return { kind: 'message', message: typeof error === 'string' ? error : '' };
}

/** What a rejected `requestCertificate` carries; anything else it was rejected with becomes a message. */
export function requestFailure(error: unknown): RequestFailure {
    if (typeof error === 'object' && error !== null && 'kind' in error) {
        return error as RequestFailure;
    }
    return { kind: 'message', message: typeof error === 'string' ? error : '' };
}

/** Closes an open form. */
export function closeForm(id: string): Promise<void> {
    return invoke<void>('close_form', { id });
}

/** Opens the page of ILM's web interface that the target names in the browser. */
export function openInIlm(target: IlmTarget): Promise<void> {
    return invoke<void>('open_in_ilm', { target });
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
