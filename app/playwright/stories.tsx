import { mockIPC, mockWindows } from '@tauri-apps/api/mocks';
import { useMemo, useState } from 'react';
import { AppInfoContext } from '../src/app-info';
import type {
    CertificateChoice,
    Change,
    IlmPageView,
    InventoryView,
    LocalCertificateView,
    LogLevel,
    Platform,
    ProviderChoice,
    SessionView,
    SettingsView,
} from '../src/bridge';
import { LockNote } from '../src/components/Switch/LockNote';
import { Select } from '../src/components/Switch/Select';
import { Shell } from '../src/components/Shell/Shell';
import { Switch } from '../src/components/Switch/Switch';
import { TraySummary } from '../src/components/TraySummary/TraySummary';
import { OverviewIcon, SettingsIcon } from '../src/design-system/icons';
import type { Section } from '../src/sections';
import { sections as realSections, settingsSection } from '../src/sections';
import { Certificates } from '../src/sections/Certificates';
import { Settings } from '../src/sections/Settings';
import { SignIn, Unreachable } from '../src/sections/SignIn';
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

type SeenProps = Readonly<{ session?: SessionView; refuse?: string; seen?: (command: string) => void }>;

/** Stands in for the commands of the summary and the unlock: each command is passed to `seen`, `refuse` rejects it. */
function useCommands({ session, refuse, seen }: SeenProps) {
    useMemo(() => {
        mockIPC(
            (command) => {
                if (command === 'session') {
                    return session;
                }
                seen?.(command);
                return refuse && (command === 'unlock' || command === 'sign_in_again') ? Promise.reject(refuse) : undefined;
            },
            { shouldMockEvents: true },
        );
    }, [session, refuse, seen]);
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

type UnreachableProps = StoryProps & Readonly<{ refuse?: string }>;

/** The sign-in that waits for ILM, against a stand-in for Sign out. */
export function UnreachableStory({ platform, refuse }: UnreachableProps) {
    useMemo(() => {
        mockIPC(() => (refuse ? Promise.reject(refuse) : undefined));
    }, [refuse]);
    return (
        <AppInfoContext.Provider value={useInfo(platform)}>
            <Unreachable view={{ state: 'unreachable', address: 'https://ilm.example.com', problem: 'ILM cannot be reached.' }} />
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
    }>;

declare global {
    interface Window {
        /** The requests the In ILM view made, as "<page>|<search>". */
        ilmRequests?: string[];
    }
}

function ilmAnswer(pages: CertificatesProps['pages'], delays: CertificatesProps['delays'], args: { page: number; search: string | null }) {
    const key = `${args.page}|${args.search ?? ''}`;
    window.ilmRequests = [...(window.ilmRequests ?? []), key];
    const found = pages?.[key] ?? pages?.['*'];
    const answer = Array.isArray(found) ? (found.length > 1 ? found.shift() : found[0]) : found;
    const settle = () => (answer && 'error' in answer ? Promise.reject(answer.error) : answer);
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
}: CertificatesProps) {
    useMemo(() => {
        window.ilmRequests = [];
        mockIPC(
            (command, args) => {
                switch (command) {
                    case 'local_certificates':
                        return certificates;
                    case 'ilm_status':
                        return inventory;
                    case 'ilm_certificates':
                        return ilmAnswer(pages, delays, args as { page: number; search: string | null });
                    case 'make_sign_in_certificate':
                        return refuseSignIn
                            ? Promise.reject(refuseSignIn)
                            : inventory && { ...inventory, signIn: (args as { fingerprint: string }).fingerprint };
                    default:
                        return undefined;
                }
            },
            { shouldMockEvents: true },
        );
    }, [certificates, inventory, pages, delays, refuseSignIn]);
    return (
        <AppInfoContext.Provider value={useInfo(platform)}>
            <main className="bg-surface p-s5" style={{ width }}>
                <Certificates />
            </main>
        </AppInfoContext.Provider>
    );
}
