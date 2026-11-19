import { mockIPC } from '@tauri-apps/api/mocks';
import { useMemo, useState } from 'react';
import { AppInfoContext } from '../src/app-info';
import type { CertificateChoice, Change, LogLevel, Platform, ProviderChoice, SessionView, SettingsView } from '../src/bridge';
import { LockNote } from '../src/components/Switch/LockNote';
import { Select } from '../src/components/Switch/Select';
import { Shell } from '../src/components/Shell/Shell';
import { Switch } from '../src/components/Switch/Switch';
import { TraySummary } from '../src/components/TraySummary/TraySummary';
import { OverviewIcon, SettingsIcon } from '../src/design-system/icons';
import type { Section } from '../src/sections';
import { sections as realSections, settingsSection } from '../src/sections';
import { Settings } from '../src/sections/Settings';
import { SignIn } from '../src/sections/SignIn';

const First = () => <p>First content</p>;
const Second = () => <p>Second content</p>;
const SettingsStub = () => <p>Settings content</p>;

const sections: Section[] = [
    { id: 'first', label: 'First', icon: OverviewIcon, Component: First },
    { id: 'second', label: 'Second', icon: OverviewIcon, Component: Second },
];

type StoryProps = Readonly<{ platform: Platform }>;

const useInfo = (platform: Platform) => useMemo(() => ({ name: 'Identity Manager', version: '0.1.0', platform }), [platform]);

export function ShellStory({ platform }: StoryProps) {
    const bottom = useMemo<Section | undefined>(
        () =>
            platform === 'macos'
                ? undefined
                : { id: 'settings', label: platform === 'linux' ? 'Preferences' : 'Settings', icon: SettingsIcon, Component: SettingsStub },
        [platform],
    );
    return (
        <AppInfoContext.Provider value={useInfo(platform)}>
            <Shell sections={sections} bottom={bottom} />
        </AppInfoContext.Provider>
    );
}

export function TraySummaryStory({ platform }: StoryProps) {
    return (
        <AppInfoContext.Provider value={useInfo(platform)}>
            <TraySummary />
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
};

type SettingsProps = StoryProps & Readonly<{ view: SettingsView; refuse?: string; session?: SessionView }>;

/** Settings against a stand-in for the commands: a change is applied to the view unless `refuse` is given. */
export function SettingsStory({ platform, view, refuse, session = signedInView }: SettingsProps) {
    useMemo(() => {
        let current = view;
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
    }, [view, refuse, session]);
    return (
        <AppInfoContext.Provider value={useInfo(platform)}>
            {platform === 'macos' ? <Settings /> : <Shell sections={realSections} bottom={settingsSection(platform)} />}
        </AppInfoContext.Provider>
    );
}

type Idle = Extract<SessionView, { state: 'signedOut' }>;
type SignInProps = StoryProps &
    Readonly<{ view: Idle; providers?: ProviderChoice[]; refuse?: string; certificates?: CertificateChoice[]; refuseCertificate?: string }>;
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
    }, [view, providers, refuse, certificates, refuseCertificate]);
    return (
        <AppInfoContext.Provider value={useInfo(platform)}>
            <SignIn view={shown} />
        </AppInfoContext.Provider>
    );
}
