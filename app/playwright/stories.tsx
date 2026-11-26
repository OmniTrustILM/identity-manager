import { mockIPC, mockWindows } from '@tauri-apps/api/mocks';
import { useMemo, useState } from 'react';
import { AppInfoContext } from '../src/app-info';
import type {
    AddChoicesView,
    AddResultView,
    AttributeFieldProblem,
    AttributeFormView,
    CertificateChoice,
    Change,
    FollowView,
    IlmPageView,
    InventoryView,
    LocalCertificateView,
    LogLevel,
    Platform,
    ProviderChoice,
    RaProfileChoice,
    ApprovalFailure,
    RequestFailure,
    RequestFormsView,
    RequestOffers,
    SessionView,
    SettingsView,
    SummaryView,
} from '../src/bridge';
import { IlmWaitingContext } from '../src/ilm-waiting';
import { LockNote } from '../src/components/Switch/LockNote';
import { AttributeForm, type AttributeState } from '../src/components/AttributeForm/AttributeForm';
import { Select } from '../src/components/Switch/Select';
import { Shell } from '../src/components/Shell/Shell';
import { Switch } from '../src/components/Switch/Switch';
import { TraySummary } from '../src/components/TraySummary/TraySummary';
import { OverviewIcon, SettingsIcon } from '../src/design-system/icons';
import type { Section } from '../src/sections';
import { sections as realSections, settingsSection, visibleSections } from '../src/sections';
import { Certificates } from '../src/sections/Certificates';
import { AddToIlm } from '../src/sections/AddToIlm';
import { Request } from '../src/sections/Request';
import { Requests } from '../src/sections/Requests';
import { Settings } from '../src/sections/Settings';
import { SignIn, UnreachableBanner } from '../src/sections/SignIn';
import { Unlock } from '../src/sections/Unlock';

const First = () => <p>First content</p>;
const Second = () => <p>Second content</p>;
const SettingsStub = () => <p>Settings content</p>;

const sections: Section[] = [
    { id: 'first', label: 'First', icon: OverviewIcon, Component: First },
    { id: 'second', label: 'Second', icon: OverviewIcon, Component: Second },
];

type StoryProps = Readonly<{ platform: Platform }>;

const useInfo = (platform: Platform) => useMemo(() => ({ name: 'Identity Manager', version: '0.1.0', platform }), [platform]);

/** The shell with two sections; on macOS its Settings… entry says so when it is asked to open the Settings window. */
export function ShellStory({ platform }: StoryProps) {
    const [windowOpened, setWindowOpened] = useState(false);
    const bottom = useMemo<Section>(
        () =>
            platform === 'macos'
                ? {
                      id: 'settings',
                      label: 'Settings\u2026',
                      icon: SettingsIcon,
                      Component: SettingsStub,
                      open: () => setWindowOpened(true),
                  }
                : { id: 'settings', label: platform === 'linux' ? 'Preferences' : 'Settings', icon: SettingsIcon, Component: SettingsStub },
        [platform],
    );
    return (
        <AppInfoContext.Provider value={useInfo(platform)}>
            <Shell sections={sections} bottom={bottom} />
            {windowOpened && <p>Settings window opened</p>}
        </AppInfoContext.Provider>
    );
}

/** How the commands of renewal answer: the renewal is refused, or followed to `follow`; the switch returns `switched`. */
export interface Renewing {
    follow?: FollowView;
    refuse?: string;
    switched?: InventoryView;
}

function renewAnswer(command: string, renewing: Renewing | undefined) {
    switch (command) {
        case 'renew_now':
            return renewing?.refuse ? Promise.reject(renewing.refuse) : { certificate: 'renewal', label: 'Renewal' };
        case 'follow_request':
            return renewing?.follow ?? { state: 'unknown' };
        case 'set_renewal_switch':
            return renewing?.switched;
        default:
            return undefined;
    }
}

type SeenProps = Readonly<{
    session?: SessionView;
    refuse?: string;
    /** What the summary shows of the certificates; none while it is not known. */
    summary?: SummaryView | null;
    seen?: (command: string, args?: unknown) => void;
    renewing?: Renewing;
}>;

/** Stands in for the commands of the summary and the unlock: each command is passed to `seen`, `refuse` rejects it. */
function useCommands({ session, refuse, summary = null, seen, renewing }: SeenProps) {
    useMemo(() => {
        mockIPC(
            (command, args) => {
                if (command === 'session') {
                    return session;
                }
                if (command === 'overview') {
                    return summary;
                }
                seen?.(command, args);
                return refuse && (command === 'unlock' || command === 'sign_in_again')
                    ? Promise.reject(refuse)
                    : renewAnswer(command, renewing);
            },
            { shouldMockEvents: true },
        );
    }, [session, refuse, summary, seen, renewing]);
}

export function TraySummaryStory({ platform, ...commands }: StoryProps & SeenProps) {
    useCommands(commands);
    return (
        <AppInfoContext.Provider value={useInfo(platform)}>
            <TraySummary />
        </AppInfoContext.Provider>
    );
}

export function UnlockStory({ platform, automatic = false, ...commands }: StoryProps & SeenProps & Readonly<{ automatic?: boolean }>) {
    useCommands(commands);
    return (
        <AppInfoContext.Provider value={useInfo(platform)}>
            <Unlock automatic={automatic} />
        </AppInfoContext.Provider>
    );
}

type ControlsProps = StoryProps & Readonly<{ locked?: boolean }>;

export function ControlsStory({ platform, locked = false }: ControlsProps) {
    const [on, setOn] = useState(true);
    const [level, setLevel] = useState<LogLevel>('info');
    return (
        <AppInfoContext.Provider value={useInfo(platform)}>
            <div className="flex flex-col items-start gap-s3 bg-surface p-s5">
                <div className="flex items-center gap-s3">
                    <label htmlFor="login">Start at login</label>
                    <Switch id="login" checked={on} onChange={setOn} />
                </div>
                <div className="flex items-center gap-s3">
                    <label htmlFor="disabled">Disabled switch</label>
                    <Switch id="disabled" checked={on} onChange={setOn} disabled />
                </div>
                <div className="flex items-center gap-s3">
                    <label htmlFor="level">Log level</label>
                    <Select
                        id="level"
                        value={level}
                        options={['error', 'warn', 'info', 'debug'] as const}
                        onChange={setLevel}
                        aria-describedby={locked ? 'note' : undefined}
                        disabled={locked}
                    />
                </div>
                {locked && <LockNote id="note" />}
            </div>
        </AppInfoContext.Provider>
    );
}

export const signedInView: SessionView = {
    state: 'signedIn',
    address: 'ilm.example.com',
    person: { name: 'Alex Morgan', username: 'alex.morgan' },
    allowedListings: [],
    certificate: null,
    unreachable: false,
};

type SettingsProps = StoryProps & Readonly<{ view: SettingsView; refuse?: string; session?: SessionView }>;

/** Settings against a stand-in for the commands: a change is applied to the view unless `refuse` is given. */
export function SettingsStory({ platform, view, refuse, session = signedInView }: SettingsProps) {
    useMemo(() => {
        let current = view;
        mockWindows(platform === 'macos' ? 'settings' : 'main');
        mockIPC((command, args) => {
            if (command === 'session') {
                return session;
            }
            if (command === 'overview' || command === 'ilm_status') {
                return null;
            }
            if (command === 'local_certificates') {
                return [];
            }
            if (command === 'connect') {
                return refuse ? Promise.reject(refuse) : [];
            }
            if (command === 'set_setting') {
                if (refuse) {
                    return Promise.reject(refuse);
                }
                const { key, value } = (args as { change: Change }).change;
                current = { ...current, [key]: { value, locked: false } } as SettingsView;
            }
            return current;
        });
    }, [platform, view, refuse, session]);
    return (
        <AppInfoContext.Provider value={useInfo(platform)}>
            {platform === 'macos' ? (
                <div className="min-h-screen bg-sidebar">
                    <Settings />
                </div>
            ) : (
                <Shell sections={realSections} bottom={settingsSection(platform)} />
            )}
        </AppInfoContext.Provider>
    );
}

type Idle = Extract<SessionView, { state: 'signedOut' }>;
type SignInProps = StoryProps &
    Readonly<{
        view: Idle;
        providers?: ProviderChoice[];
        refuse?: string;
        certificates?: CertificateChoice[];
        refuseCertificate?: string;
        again?: ProviderChoice[];
    }>;
const noProviders: ProviderChoice[] = [];
const noCertificates: CertificateChoice[] = [];

/** The sign-in against a stand-in for the commands: signing in moves it to Waiting and Cancel moves it back. */
export function SignInStory({
    platform,
    view,
    providers = noProviders,
    refuse,
    certificates = noCertificates,
    refuseCertificate,
    again = noProviders,
}: SignInProps) {
    const [shown, setShown] = useState<Idle | Extract<SessionView, { state: 'signingIn' }>>(view);
    useMemo(() => {
        mockIPC((command, args) => {
            switch (command) {
                case 'connect':
                    return refuse ? Promise.reject(refuse) : providers;
                case 'sign_in': {
                    const { providerId } = args as { providerId: string };
                    setShown({
                        state: 'signingIn',
                        method: 'browser',
                        provider: providers.find((provider) => provider.id === providerId)?.name ?? '',
                    });
                    return new Promise(() => undefined);
                }
                case 'sign_in_again':
                    return refuse ? Promise.reject(refuse) : again;
                case 'certificates':
                    return certificates;
                case 'sign_in_with_certificate':
                    if (refuseCertificate) {
                        return Promise.reject(refuseCertificate);
                    }
                    setShown({ state: 'signingIn', method: 'certificate', provider: 'Certificate on this computer' });
                    return new Promise(() => undefined);
                case 'cancel_sign_in':
                    setShown(view);
                    return undefined;
                default:
                    return undefined;
            }
        });
    }, [view, providers, refuse, certificates, refuseCertificate, again]);
    return (
        <AppInfoContext.Provider value={useInfo(platform)}>
            <SignIn view={shown} />
        </AppInfoContext.Provider>
    );
}

type UnreachableProps = StoryProps &
    Readonly<{
        refuse?: string;
        certificates: LocalCertificateView[];
        /** What ILM was last known to say; null when nothing was kept. */
        inventory: InventoryView | null;
    }>;

/** The shell of a saved sign-in that waits for ILM: the banner with Sign out, over the sections with the kept answer. */
export function UnreachableStory({ platform, refuse, certificates, inventory }: UnreachableProps) {
    useMemo(() => {
        mockIPC(
            (command) => {
                switch (command) {
                    case 'local_certificates':
                        return certificates;
                    case 'ilm_status':
                        return inventory;
                    case 'sign_out':
                        return refuse ? Promise.reject(refuse) : undefined;
                    default:
                        return undefined;
                }
            },
            { shouldMockEvents: true },
        );
    }, [certificates, inventory, refuse]);
    return (
        <AppInfoContext.Provider value={useInfo(platform)}>
            <IlmWaitingContext.Provider value>
                <Shell
                    sections={visibleSections([], platform)}
                    bottom={settingsSection(platform)}
                    banner={
                        <UnreachableBanner
                            view={{
                                state: 'unreachable',
                                address: 'https://ilm.example.com',
                                problem: 'The identity provider cannot be reached.',
                            }}
                        />
                    }
                />
            </IlmWaitingContext.Provider>
        </AppInfoContext.Provider>
    );
}

/** What ILM answers for a page: the page, or a refusal; a list is used up one answer at a time, the last one stays. */
export type IlmAnswer = IlmPageView | { error: string };
type CertificatesProps = StoryProps &
    Readonly<{
        certificates: LocalCertificateView[];
        width?: number;
        /** What ILM is known to say; null while it is not known. */
        inventory?: InventoryView | null;
        /** The answers of the In ILM view by "<page>|<search>"; "*" answers any other request. */
        pages?: Record<string, IlmAnswer | IlmAnswer[]>;
        /** Milliseconds an answer to a request takes, by the same keys. */
        delays?: Record<string, number>;
        /** Rejects the sign-in certificate change with this reason. */
        refuseSignIn?: string;
        /** How the certificates stand, as the summary says; the expiring ones are shown in the colour of attention. */
        summary?: SummaryView | null;
        /** What ILM lets the person choose when adding, and how each certificate fares. */
        adding?: Adding;
        /** What ILM lets the person request. */
        requesting?: Requesting;
        /** How renewing answers. */
        renewing?: Renewing;
    }>;

interface Adding {
    choices?: AddChoicesView;
    /** Rejects the listing of the choices. */
    refuseChoices?: boolean;
    results?: AddResultView[];
    /** Rejects the add with this reason. */
    refuse?: string;
    /** Milliseconds the add takes. */
    delay?: number;
    /** What the check of the form finds. */
    problems?: AttributeFieldProblem[];
    /** Rejects the add with these problems of the form. */
    refuseProblems?: AttributeFieldProblem[];
    /** Told of the commands of the form and of the add. */
    seen?: (command: string, args?: unknown) => void;
}

const noChoices: AddChoicesView = { groups: null, raProfiles: null, customAttributes: null };

/** Answers the commands of the Add to ILM dialog from `adding`; anything else is not its business. */
function addAnswer(command: string, adding: Adding | undefined, args?: unknown) {
    switch (command) {
        case 'add_to_ilm_choices':
            return adding?.refuseChoices ? Promise.reject('no') : (adding?.choices ?? noChoices);
        case 'check_attributes':
            return { revision: adding?.choices?.customAttributes?.revision ?? 0, problems: adding?.problems ?? [] };
        case 'close_form':
        case 'open_in_ilm':
            adding?.seen?.(command, args);
            return undefined;
        default: {
            adding?.seen?.(command, args);
            if (adding?.refuseProblems) {
                return Promise.reject({ problems: adding.refuseProblems });
            }
            const settle = () => (adding?.refuse ? Promise.reject(adding.refuse) : (adding?.results ?? []));
            return adding?.delay ? new Promise((resolve) => setTimeout(resolve, adding.delay)).then(settle) : settle();
        }
    }
}

/** What the commands of the request wizard answer. */
export interface Requesting {
    profiles: RaProfileChoice[];
    forms?: RequestFormsView;
    offers?: RequestOffers;
    /** Rejects the request with this. */
    refuse?: RequestFailure;
    /** Rejects a decision on an approval with this. */
    refuseDecision?: ApprovalFailure;
    /** How the request stands at each follow; the last answer stays. */
    follow?: FollowView[];
    /** What the check of a form finds. */
    problems?: AttributeFieldProblem[];
    /** Told of the commands of the wizard. */
    seen?: (command: string, args?: unknown) => void;
}

const noForms: RequestFormsView = { request: null, issue: null, custom: null };
const noOffers: RequestOffers = { storages: [], defaultStorage: null };

function requestAnswer(command: string, requesting: Requesting | undefined, args?: unknown) {
    requesting?.seen?.(command, args);
    switch (command) {
        case 'request_choices':
            return requesting?.profiles ?? [];
        case 'open_request_forms':
        case 'open_prepared_forms':
            return requesting?.forms ?? noForms;
        case 'request_offers':
            return requesting?.offers ?? noOffers;
        case 'check_attributes':
            return { revision: 0, problems: requesting?.problems ?? [] };
        case 'request_certificate':
        case 'complete_certificate':
            return requesting?.refuse ? Promise.reject(requesting.refuse) : { certificate: 'cert-1', label: 'User mTLS' };
        case 'decide_approval':
            return requesting?.refuseDecision ? Promise.reject(requesting.refuseDecision) : undefined;
        case 'follow_request': {
            const answers = requesting?.follow ?? [{ state: 'unknown' }];
            return answers.length > 1 ? answers.shift() : answers[0];
        }
        default:
            return undefined;
    }
}

type RequestProps = StoryProps & Readonly<{ requesting: Requesting; onClose?: () => void }>;

/** The request wizard over an empty page, against a stand-in for the commands. */
export function RequestStory({ platform, requesting, onClose }: RequestProps) {
    const [open, setOpen] = useState(true);
    useMemo(() => {
        mockIPC((command, args) => requestAnswer(command, requesting, args));
    }, [requesting]);
    return (
        <AppInfoContext.Provider value={useInfo(platform)}>
            <main className="min-h-screen bg-surface p-s5">
                {open && (
                    <Request
                        profiles={requesting.profiles}
                        platform={platform}
                        onClose={() => {
                            setOpen(false);
                            onClose?.();
                        }}
                    />
                )}
            </main>
        </AppInfoContext.Provider>
    );
}

type RequestsProps = StoryProps & Readonly<{ inventory: InventoryView | null; requesting?: Requesting }>;

/** The Requests section against a stand-in for its commands and for the wizard behind Issue…. */
export function RequestsStory({ platform, inventory, requesting }: RequestsProps) {
    useMemo(() => {
        mockIPC((command, args) => (command === 'ilm_status' ? inventory : requestAnswer(command, requesting, args)), {
            shouldMockEvents: true,
        });
    }, [inventory, requesting]);
    return (
        <AppInfoContext.Provider value={useInfo(platform)}>
            <main className="min-h-screen bg-surface p-s5">
                <Requests />
            </main>
        </AppInfoContext.Provider>
    );
}

declare global {
    interface Window {
        /** The requests the In ILM view made, as "<page>|<search>". */
        ilmRequests?: string[];
        /** The requests of the In ILM view that were answered, as "<page>|<search>". */
        ilmAnswered?: string[];
    }
}

function ilmAnswer(pages: CertificatesProps['pages'], delays: CertificatesProps['delays'], args: { page: number; search: string | null }) {
    const key = `${args.page}|${args.search ?? ''}`;
    window.ilmRequests = [...(window.ilmRequests ?? []), key];
    const found = pages?.[key] ?? pages?.['*'];
    const answer = Array.isArray(found) ? (found.length > 1 ? found.shift() : found[0]) : found;
    const settle = () => {
        window.ilmAnswered = [...(window.ilmAnswered ?? []), key];
        return answer && 'error' in answer ? Promise.reject(answer.error) : answer;
    };
    const wait = delays?.[key];
    return wait ? new Promise((resolve) => setTimeout(resolve, wait)).then(settle) : settle();
}

/** The Certificates section against a stand-in for its commands, in a window of the given width. */
export function CertificatesStory({
    platform,
    certificates,
    width = 1000,
    inventory = null,
    pages,
    delays,
    refuseSignIn,
    summary = null,
    adding,
    requesting,
    renewing,
}: CertificatesProps) {
    useMemo(() => {
        window.ilmRequests = [];
        window.ilmAnswered = [];
        mockIPC(
            (command, args) => {
                switch (command) {
                    case 'local_certificates':
                        return certificates;
                    case 'ilm_status':
                        return inventory;
                    case 'ilm_certificates':
                        return ilmAnswer(pages, delays, args as { page: number; search: string | null });
                    case 'overview':
                        return summary;
                    case 'add_to_ilm_choices':
                    case 'add_to_ilm':
                        return addAnswer(command, adding);
                    case 'request_choices':
                    case 'open_request_forms':
                    case 'request_offers':
                    case 'request_certificate':
                    case 'check_attributes':
                    case 'close_form':
                        return requestAnswer(command, requesting);
                    case 'follow_request':
                        return renewing ? renewAnswer(command, renewing) : requestAnswer(command, requesting);
                    case 'make_sign_in_certificate':
                        return refuseSignIn
                            ? Promise.reject(refuseSignIn)
                            : inventory && { ...inventory, signIn: (args as { fingerprint: string }).fingerprint };
                    default:
                        return renewAnswer(command, renewing);
                }
            },
            { shouldMockEvents: true },
        );
    }, [certificates, inventory, pages, delays, refuseSignIn, summary, adding, requesting, renewing]);
    return (
        <AppInfoContext.Provider value={useInfo(platform)}>
            <main className="bg-surface p-s5" style={{ width }}>
                <Certificates />
            </main>
        </AppInfoContext.Provider>
    );
}

type OverviewProps = StoryProps &
    Readonly<{
        summary: SummaryView | null;
        certificates: LocalCertificateView[];
        inventory: InventoryView | null;
        adding?: Adding;
        /** The saved sign-in waits for ILM. */
        waiting?: boolean;
        renewing?: Renewing;
    }>;

/** The shell on Overview, against a stand-in for the commands, so that Show can open Certificates. */
export function OverviewStory({ platform, summary, certificates, inventory, adding, waiting = false, renewing }: OverviewProps) {
    useMemo(() => {
        mockIPC(
            (command) => {
                switch (command) {
                    case 'overview':
                        return summary;
                    case 'local_certificates':
                        return certificates;
                    case 'ilm_status':
                    case 'sync_now':
                        return inventory;
                    case 'add_to_ilm_choices':
                    case 'add_to_ilm':
                        return addAnswer(command, adding);
                    default:
                        return renewAnswer(command, renewing);
                }
            },
            { shouldMockEvents: true },
        );
    }, [summary, certificates, inventory, adding, renewing]);
    return (
        <AppInfoContext.Provider value={useInfo(platform)}>
            <IlmWaitingContext.Provider value={waiting}>
                <Shell sections={visibleSections(['certificates'], platform)} bottom={settingsSection(platform)} />
            </IlmWaitingContext.Provider>
        </AppInfoContext.Provider>
    );
}

type AddProps = StoryProps & Readonly<{ certificates: LocalCertificateView[]; adding?: Adding; onClose?: () => void }>;

/** The Add to ILM dialog over an empty page, against a stand-in for the commands. */
export function AddToIlmStory({ platform, certificates, adding, onClose }: AddProps) {
    const [open, setOpen] = useState(true);
    useMemo(() => {
        mockIPC((command, args) => addAnswer(command, adding, args));
    }, [adding]);
    return (
        <AppInfoContext.Provider value={useInfo(platform)}>
            <main className="min-h-screen bg-surface p-s5">
                <button type="button" onClick={() => setOpen(true)}>
                    Open
                </button>
                {open && (
                    <AddToIlm
                        certificates={certificates}
                        system={platform === 'macos' ? 'macos' : 'windows'}
                        onClose={() => {
                            setOpen(false);
                            onClose?.();
                        }}
                    />
                )}
            </main>
        </AppInfoContext.Provider>
    );
}

/** What a field's callback answers with: a form, or what ILM said, after a delay; answers are used in turn and the last repeats. */
export interface CallbackAnswer {
    form?: AttributeFormView;
    problem?: string;
    delay?: number;
}

type FormProps = StoryProps &
    Readonly<{
        form: AttributeFormView;
        /** What the check of the form finds. */
        problems?: AttributeFieldProblem[];
        answers?: Record<string, CallbackAnswer[]>;
        submitted?: boolean;
        disabled?: boolean;
        seen?: (command: string, args?: unknown) => void;
    }>;

/** The attribute form on its own, against stand-ins for its commands; the values and whether the form may be sent are shown below it. */
const noProblems: AttributeFieldProblem[] = [];
const noAnswers: Record<string, CallbackAnswer[]> = {};

export function AttributeFormStory({
    platform,
    form,
    problems = noProblems,
    answers = noAnswers,
    submitted = false,
    disabled = false,
    seen,
}: FormProps) {
    const [state, setState] = useState<AttributeState>({ values: {}, ready: false, blocked: false });
    useMemo(() => {
        const used: Record<string, number> = {};
        let revision = form.revision;
        mockIPC((command, args) => {
            seen?.(command, args);
            if (command === 'check_attributes') {
                return { revision, problems };
            }
            if (command === 'attribute_callback') {
                const { field, seq } = args as { field: string; seq: number };
                const list = answers[field] ?? [];
                const turn = used[field] ?? 0;
                used[field] = turn + 1;
                const answer = list[Math.min(turn, list.length - 1)];
                const next = answer?.form ?? form;
                revision = Math.max(revision, next.revision);
                const result = { seq, field, form: next, problem: answer?.problem ?? null };
                if (!answer?.delay) {
                    return result;
                }
                return new Promise((resolve) => setTimeout(resolve, answer.delay)).then(() => {
                    seen?.('attribute_callback_answered', { field });
                    return result;
                });
            }
            return undefined;
        });
    }, [form, problems, answers, seen]);
    return (
        <AppInfoContext.Provider value={useInfo(platform)}>
            <div className="flex w-form flex-col gap-s3 bg-surface p-s5 text-primary">
                <AttributeForm form={form} target="addToIlm" disabled={disabled} submitted={submitted} onChange={setState} />
                <p data-testid="ready">{state.ready ? 'ready' : 'not ready'}</p>
                <pre data-testid="values" className="whitespace-pre-wrap break-all text-caption">
                    {JSON.stringify(state.values)}
                </pre>
            </div>
        </AppInfoContext.Provider>
    );
}
