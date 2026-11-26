import { Fragment, type ReactNode, useEffect, useId, useRef, useState } from 'react';
import { useAppInfo } from '../app-info';
import {
    type AutomaticRenewal,
    type Change,
    connect,
    getSettings,
    type LogLevel,
    type Platform,
    setSetting,
    type SettingsView,
    signOut,
} from '../bridge';
import { ConnectionIcon, InfoIcon, LockIcon, SettingsIcon } from '../design-system/icons';
import { LockNote } from '../components/Switch/LockNote';
import { Select } from '../components/Switch/Select';
import { Switch } from '../components/Switch/Switch';
import { TextField } from '../components/TextField/TextField';
import { useSession } from '../session';
import { strings } from '../strings';
import { type Pane, SettingsTabs } from './SettingsTabs';
import { Unlock } from './Unlock';

const logLevels: readonly LogLevel[] = ['error', 'warn', 'info', 'debug'];
const checkChoices = [5, 15, 30, 60];
const warnChoices = [7, 14, 30, 60, 90];
const renewalChoices: readonly AutomaticRenewal[] = ['off', 'newKey', 'sameKey'];
const idleChoices = [null, 5, 15, 30, 60];

const idleKey = (minutes: number | null) => (minutes === null ? 'never' : String(minutes));
const idleLabel = (key: string) => (key === 'never' ? strings.never : strings.minutes(Number(key)));

interface ControlProps {
    id: string;
    disabled: boolean;
    'aria-describedby'?: string;
}

interface RowProps {
    label: string;
    locked: boolean;
    /** Disabled for a reason of its own, which `note` gives. */
    disabled?: boolean;
    note?: string;
    error?: string;
    renderControl: (props: ControlProps) => ReactNode;
}

const rowClass =
    'border-separator px-s4 py-s3 in-data-[os=windows]:rounded-control in-data-[os=windows]:border in-data-[os=windows]:bg-card';

function Row({ label, locked, disabled = false, note, error, renderControl }: Readonly<RowProps>) {
    const id = useId();
    const lockId = `${id}-lock`;
    const errorId = `${id}-error`;
    const noteId = `${id}-note`;
    const describedBy = [locked && lockId, note && noteId, error && errorId].filter(Boolean).join(' ');

    return (
        <div className={rowClass}>
            <div className="flex items-center justify-between gap-s4">
                <div className="flex flex-col gap-s1">
                    <label htmlFor={id} className="text-body text-primary">
                        {label}
                    </label>
                    {locked && <LockNote id={lockId} />}
                    {note && (
                        <p id={noteId} className="flex items-center gap-s1 text-caption text-secondary">
                            <InfoIcon aria-hidden className="size-icon shrink-0" />
                            {note}
                        </p>
                    )}
                </div>
                {renderControl({
                    id,
                    disabled: locked || disabled,
                    'aria-describedby': describedBy || undefined,
                })}
            </div>
            {error && (
                <p id={errorId} role="alert" className="pt-s2 text-caption text-bad">
                    {error}
                </p>
            )}
        </div>
    );
}

function Group({ title, children }: Readonly<{ title: string; children: ReactNode }>) {
    const id = useId();
    return (
        <section aria-labelledby={id} className="flex flex-col gap-s3">
            <h2 id={id} className="text-title font-semibold in-data-[os=macos]:sr-only">
                {title}
            </h2>
            <div className="flex flex-col divide-y divide-separator overflow-hidden rounded-window border border-separator bg-card in-data-[os=windows]:gap-s1 in-data-[os=windows]:overflow-visible in-data-[os=windows]:border-0 in-data-[os=windows]:bg-transparent">
                {children}
            </div>
        </section>
    );
}

interface SecurityProps {
    view: SettingsView;
    platform: Platform;
    errors: Partial<Record<Change['key'], string>>;
    change: (next: Change) => void;
}

/** Locking the application: whether the system confirms the person, and after how long without input. */
function Security({ view, platform, errors, change }: Readonly<SecurityProps>) {
    const ready = view.unlock === 'available';
    const minutes = view.lockAfterIdle.value;
    const options = (idleChoices.includes(minutes) ? idleChoices : [...idleChoices, minutes]).map(idleKey);
    let note: string | undefined;
    if (!ready) {
        note = platform === 'windows' ? strings.setUpHello : strings.setUpPassword;
    }
    return (
        <Group title={strings.security}>
            <Row
                label={platform === 'windows' ? strings.unlockWithHello : strings.unlockWithTouchId}
                locked={view.requireUnlock.locked}
                disabled={!ready}
                note={note}
                error={errors.requireUnlock}
                renderControl={(props) => (
                    <Switch
                        {...props}
                        checked={ready && view.requireUnlock.value}
                        onChange={(value) => change({ key: 'requireUnlock', value })}
                    />
                )}
            />
            <Row
                label={strings.lockAfterIdle}
                locked={view.lockAfterIdle.locked}
                disabled={!ready || !view.requireUnlock.value}
                error={errors.lockAfterIdle}
                renderControl={(props) => (
                    <Select
                        {...props}
                        value={idleKey(minutes)}
                        options={options}
                        label={idleLabel}
                        onChange={(key) => change({ key: 'lockAfterIdle', value: key === 'never' ? null : Number(key) })}
                    />
                )}
            />
        </Group>
    );
}

interface AddressRowProps {
    address: string;
    locked: boolean;
    readOnly: boolean;
}

/** The ILM address in use; confirming another one connects to it, which signs the person out of the old one. */
function AddressRow({ address, locked, readOnly }: Readonly<AddressRowProps>) {
    const [draft, setDraft] = useState(address);
    const [error, setError] = useState<string>();

    useEffect(() => setDraft(address), [address]);

    const confirm = () => {
        const next = draft.trim();
        if (next === address) {
            return;
        }
        setError(undefined);
        connect(next).catch((error_) => {
            setDraft(address);
            setError(String(error_) || strings.settingFailed);
        });
    };

    return (
        <Row
            label={strings.ilmAddress}
            locked={locked}
            error={error}
            renderControl={(props) => (
                <div className="w-1/2">
                    <TextField
                        {...props}
                        value={draft}
                        readOnly={readOnly}
                        onChange={(event) => setDraft(event.target.value)}
                        onBlur={confirm}
                        onKeyDown={(event) => event.key === 'Enter' && confirm()}
                    />
                </div>
            )}
        />
    );
}

export function Settings() {
    const { platform } = useAppInfo();
    const { view: session, failed: sessionFailed } = useSession();
    const [view, setView] = useState<SettingsView | null>(null);
    const [loadFailed, setLoadFailed] = useState(false);
    const [errors, setErrors] = useState<Partial<Record<Change['key'], string>>>({});

    // Only the reply to the latest request is shown, and a row's error follows its latest change; an older reply
    // would bring back a stale view or error.
    const latest = useRef(0);
    const latestChange = useRef<Partial<Record<Change['key'], number>>>({});

    useEffect(() => {
        const load = () => {
            const request = ++latest.current;
            getSettings().then(
                (loaded) => {
                    if (request === latest.current) {
                        setView(loaded);
                        setLoadFailed(false);
                    }
                },
                () => request === latest.current && setLoadFailed(true),
            );
        };
        load();
        window.addEventListener('focus', load);
        return () => {
            latest.current++;
            window.removeEventListener('focus', load);
        };
    }, []);

    if (session?.state === 'locked') {
        return <Unlock automatic={false} />;
    }
    if (loadFailed) {
        return (
            <p role="alert" className="in-data-[os=macos]:p-s4 in-data-[os=macos]:pt-titlebar">
                {strings.settingsLoadError}
            </p>
        );
    }
    // The macOS tabs wait for the session too, or the Connection tab would be missing and its remembered choice lost.
    if (!view || (platform === 'macos' && !session && !sessionFailed)) {
        return null;
    }

    const change = async (next: Change) => {
        const shown = view;
        setView({
            ...shown,
            [next.key]: { ...shown[next.key], value: next.value },
        });
        const request = ++latest.current;
        latestChange.current[next.key] = request;
        const isLatestChange = () => latestChange.current[next.key] === request;
        try {
            const saved = await setSetting(next);
            if (request === latest.current) {
                setView(saved);
            }
            if (isLatestChange()) {
                setErrors((previous) => ({
                    ...previous,
                    [next.key]: undefined,
                }));
            }
        } catch (error) {
            if (isLatestChange()) {
                setErrors((previous) => ({
                    ...previous,
                    [next.key]: String(error) || strings.settingFailed,
                }));
            }
            if (request === latest.current) {
                setView(shown);
                const reload = ++latest.current;
                getSettings().then(
                    (loaded) => reload === latest.current && setView(loaded),
                    () => undefined,
                );
            }
        }
    };

    const panes: [Pane, ...Pane[]] = [
        {
            id: 'general',
            title: strings.general,
            icon: SettingsIcon,
            content: (
                <Group title={strings.general}>
                    <Row
                        label={strings.startAtLogin}
                        locked={view.startAtLogin.locked}
                        error={errors.startAtLogin}
                        renderControl={(props) => (
                            <Switch
                                {...props}
                                checked={view.startAtLogin.value}
                                onChange={(value) => change({ key: 'startAtLogin', value })}
                            />
                        )}
                    />
                    <Row
                        label={strings.logLevel}
                        locked={view.logLevel.locked}
                        error={errors.logLevel}
                        renderControl={(props) => (
                            <Select
                                {...props}
                                value={view.logLevel.value}
                                options={logLevels}
                                onChange={(value) => change({ key: 'logLevel', value })}
                            />
                        )}
                    />
                    <Row
                        label={strings.checkEvery}
                        locked={view.checkEvery.locked}
                        error={errors.checkEvery}
                        renderControl={(props) => (
                            <Select
                                {...props}
                                value={String(view.checkEvery.value)}
                                options={(checkChoices.includes(view.checkEvery.value)
                                    ? checkChoices
                                    : [...checkChoices, view.checkEvery.value]
                                ).map(String)}
                                label={(key) => strings.minutes(Number(key))}
                                onChange={(key) => change({ key: 'checkEvery', value: Number(key) })}
                            />
                        )}
                    />
                    <Row
                        label={strings.warnBeforeExpiry}
                        locked={view.warnDays.locked}
                        error={errors.warnDays}
                        renderControl={(props) => (
                            <Select
                                {...props}
                                value={String(view.warnDays.value)}
                                options={(warnChoices.includes(view.warnDays.value)
                                    ? warnChoices
                                    : [...warnChoices, view.warnDays.value]
                                ).map(String)}
                                label={(key) => strings.days(Number(key))}
                                onChange={(key) => change({ key: 'warnDays', value: Number(key) })}
                            />
                        )}
                    />
                    {platform !== 'linux' && (
                        <Row
                            label={strings.automaticRenewal}
                            locked={view.automaticRenewal.locked}
                            error={errors.automaticRenewal}
                            renderControl={(props) => (
                                <Select
                                    {...props}
                                    value={view.automaticRenewal.value}
                                    options={renewalChoices}
                                    label={(choice) => strings.automaticRenewalChoices[choice]}
                                    onChange={(value) => change({ key: 'automaticRenewal', value })}
                                />
                            )}
                        />
                    )}
                </Group>
            ),
        },
    ];
    if (view.unlock !== 'unsupported') {
        panes.push({
            id: 'security',
            title: strings.security,
            icon: LockIcon,
            content: <Security view={view} platform={platform} errors={errors} change={change} />,
        });
    }
    if (session?.state === 'signedIn') {
        panes.push({
            id: 'connection',
            title: strings.connection,
            icon: ConnectionIcon,
            content: (
                <Group title={strings.connection}>
                    <AddressRow address={session.address} locked={view.ilmUrl.locked} readOnly={platform === 'macos'} />
                    <div className={`flex items-center justify-between gap-s4 ${rowClass}`}>
                        <div className="flex flex-col">
                            <p className="text-body text-primary">
                                {session.certificate ? strings.signedInWithCertificate : session.person.name}
                            </p>
                            <p className="text-caption text-secondary">{session.certificate ?? session.person.username}</p>
                        </div>
                        <button
                            type="button"
                            tabIndex={0}
                            onClick={() => signOut().catch(() => undefined)}
                            className="h-control rounded-control border border-input-edge bg-input px-s3 text-body text-primary"
                        >
                            {strings.signOut}
                        </button>
                    </div>
                </Group>
            ),
        });
    }

    if (platform === 'macos') {
        return <SettingsTabs panes={panes} />;
    }
    return (
        <div className="flex flex-col gap-s3">
            <h1 className="text-large-title font-semibold in-data-[os=linux]:-mx-s5 in-data-[os=linux]:-mt-s5 in-data-[os=linux]:mb-s2 in-data-[os=linux]:bg-titlebar in-data-[os=linux]:py-s3 in-data-[os=linux]:text-center in-data-[os=linux]:text-title">
                {platform === 'linux' ? strings.preferences : strings.settings}
            </h1>
            {panes.map((pane) => (
                <Fragment key={pane.id}>{pane.content}</Fragment>
            ))}
        </div>
    );
}
