import { type ReactNode, useEffect, useId, useRef, useState } from 'react';
import { useAppInfo } from '../app-info';
import { type Change, connect, getSettings, type LogLevel, setSetting, type SettingsView, signOut } from '../bridge';
import { LockNote } from '../components/Switch/LockNote';
import { Select } from '../components/Switch/Select';
import { Switch } from '../components/Switch/Switch';
import { TextField } from '../components/TextField/TextField';
import { useSession } from '../session';
import { strings } from '../strings';

const logLevels: readonly LogLevel[] = ['error', 'warn', 'info', 'debug'];

interface ControlProps {
    id: string;
    disabled: boolean;
    'aria-describedby'?: string;
}

interface RowProps {
    label: string;
    locked: boolean;
    error?: string;
    renderControl: (props: ControlProps) => ReactNode;
}

const rowClass =
    'border-separator px-s4 py-s3 in-data-[os=windows]:rounded-control in-data-[os=windows]:border in-data-[os=windows]:bg-card';

function Row({ label, locked, error, renderControl }: Readonly<RowProps>) {
    const id = useId();
    const lockId = `${id}-lock`;
    const errorId = `${id}-error`;
    const describedBy = [locked && lockId, error && errorId].filter(Boolean).join(' ');

    return (
        <div className={rowClass}>
            <div className="flex items-center justify-between gap-s4">
                <div className="flex flex-col gap-s1">
                    <label htmlFor={id} className="text-body text-primary">
                        {label}
                    </label>
                    {locked && <LockNote id={lockId} />}
                </div>
                {renderControl({ id, disabled: locked, 'aria-describedby': describedBy || undefined })}
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
            <h2 id={id} className="text-title font-semibold">
                {title}
            </h2>
            <div className="flex flex-col divide-y divide-separator overflow-hidden rounded-window border border-separator bg-card in-data-[os=windows]:gap-s1 in-data-[os=windows]:overflow-visible in-data-[os=windows]:border-0 in-data-[os=windows]:bg-transparent">
                {children}
            </div>
        </section>
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
        connect(next).catch((failure) => {
            setDraft(address);
            setError(String(failure) || strings.settingFailed);
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
    const { view: session } = useSession();
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

    if (loadFailed) {
        return <p role="alert">{strings.settingsLoadError}</p>;
    }
    if (!view) {
        return null;
    }

    const change = async (next: Change) => {
        const shown = view;
        setView({ ...shown, [next.key]: { ...shown[next.key], value: next.value } });
        const request = ++latest.current;
        latestChange.current[next.key] = request;
        const isLatestChange = () => latestChange.current[next.key] === request;
        try {
            const saved = await setSetting(next);
            if (request === latest.current) {
                setView(saved);
            }
            if (isLatestChange()) {
                setErrors((previous) => ({ ...previous, [next.key]: undefined }));
            }
        } catch (error) {
            if (isLatestChange()) {
                setErrors((previous) => ({ ...previous, [next.key]: String(error) || strings.settingFailed }));
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

    return (
        <div className="flex flex-col gap-s3 in-data-[os=macos]:min-h-screen in-data-[os=macos]:bg-sidebar in-data-[os=macos]:p-s4">
            {platform !== 'macos' && (
                <h1 className="text-large-title font-semibold in-data-[os=linux]:-mx-s5 in-data-[os=linux]:-mt-s5 in-data-[os=linux]:mb-s2 in-data-[os=linux]:bg-titlebar in-data-[os=linux]:py-s3 in-data-[os=linux]:text-center in-data-[os=linux]:text-title">
                    {platform === 'linux' ? strings.preferences : strings.settings}
                </h1>
            )}
            <Group title={strings.general}>
                <Row
                    label={strings.startAtLogin}
                    locked={view.startAtLogin.locked}
                    error={errors.startAtLogin}
                    renderControl={(props) => (
                        <Switch {...props} checked={view.startAtLogin.value} onChange={(value) => change({ key: 'startAtLogin', value })} />
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
            </Group>
            {session?.state === 'signedIn' && (
                <Group title={strings.connection}>
                    <AddressRow address={session.address} locked={view.ilmUrl.locked} readOnly={platform === 'macos'} />
                    <div className={`flex items-center justify-between gap-s4 ${rowClass}`}>
                        <div className="flex flex-col">
                            <p className="text-body text-primary">{session.person.name}</p>
                            <p className="text-caption text-secondary">{session.person.username}</p>
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
            )}
        </div>
    );
}
