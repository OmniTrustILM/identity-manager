import { type ReactNode, useEffect, useId, useRef, useState } from 'react';
import { useAppInfo } from '../app-info';
import { type Change, getSettings, type LogLevel, setSetting, type SettingsView } from '../bridge';
import { LockNote } from '../components/Switch/LockNote';
import { Select } from '../components/Switch/Select';
import { Switch } from '../components/Switch/Switch';
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

function Row({ label, locked, error, renderControl }: Readonly<RowProps>) {
    const id = useId();
    const lockId = `${id}-lock`;
    const errorId = `${id}-error`;
    const describedBy = [locked && lockId, error && errorId].filter(Boolean).join(' ');

    return (
        <div className="border-separator px-s4 py-s3 in-data-[os=windows]:rounded-control in-data-[os=windows]:border in-data-[os=windows]:bg-card">
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

export function Settings() {
    const { platform } = useAppInfo();
    const groupId = useId();
    const [view, setView] = useState<SettingsView | null>(null);
    const [loadFailed, setLoadFailed] = useState(false);
    const [errors, setErrors] = useState<Partial<Record<Change['key'], string>>>({});

    // Only the reply to the latest request is shown; an older reply would bring back a stale view.
    const latest = useRef(0);

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
        try {
            const saved = await setSetting(next);
            if (request === latest.current) {
                setView(saved);
            }
            setErrors((previous) => ({ ...previous, [next.key]: undefined }));
        } catch (error) {
            setErrors((previous) => ({ ...previous, [next.key]: String(error) || strings.settingFailed }));
            if (request === latest.current) {
                setView(shown);
            }
            const reload = ++latest.current;
            getSettings().then(
                (loaded) => reload === latest.current && setView(loaded),
                () => undefined,
            );
        }
    };

    return (
        <div className="flex flex-col gap-s3 in-data-[os=macos]:min-h-screen in-data-[os=macos]:bg-sidebar in-data-[os=macos]:p-s4">
            {platform !== 'macos' && (
                <h1 className="text-large-title font-semibold in-data-[os=linux]:-mx-s5 in-data-[os=linux]:-mt-s5 in-data-[os=linux]:mb-s2 in-data-[os=linux]:bg-titlebar in-data-[os=linux]:py-s3 in-data-[os=linux]:text-center in-data-[os=linux]:text-title">
                    {platform === 'linux' ? strings.preferences : strings.settings}
                </h1>
            )}
            <section aria-labelledby={groupId} className="flex flex-col gap-s3">
                <h2 id={groupId} className="text-title font-semibold">
                    {strings.general}
                </h2>
                <div className="flex flex-col divide-y divide-separator overflow-hidden rounded-window border border-separator bg-card in-data-[os=windows]:gap-s1 in-data-[os=windows]:overflow-visible in-data-[os=windows]:border-0 in-data-[os=windows]:bg-transparent">
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
                </div>
            </section>
        </div>
    );
}
