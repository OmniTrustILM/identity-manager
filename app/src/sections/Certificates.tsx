import { type KeyboardEvent, type ReactNode, useCallback, useEffect, useId, useRef, useState } from 'react';
import { useAppInfo } from '../app-info';
import { type KeyAlgorithm, type LocalCertificateView, localCertificates, type Use } from '../bridge';
import { strings } from '../strings';

/** At most one request this often when the window comes back; the request the first answer needs is not delayed. */
const refreshEvery = 2000;
const fingerprintLineBytes = 16;
const dayMs = 24 * 60 * 60 * 1000;

type State = { kind: 'loading' } | { kind: 'ready'; items: LocalCertificateView[] } | { kind: 'error'; message: string };

const startOfDay = (time: number) => new Date(time).setHours(0, 0, 0, 0);

function status(certificate: LocalCertificateView, now: number): { text: string; expired: boolean } {
    if (certificate.notAfter <= now) {
        return { text: strings.expiredOn(strings.date(certificate.notAfter)), expired: true };
    }
    if (certificate.notBefore > now) {
        return { text: strings.validFromDate(strings.date(certificate.notBefore)), expired: false };
    }
    const days = Math.round((startOfDay(certificate.notAfter) - startOfDay(now)) / dayMs);
    if (days === 0) {
        return { text: strings.expiresToday, expired: false };
    }
    return { text: days === 1 ? strings.expiresTomorrow : strings.expiresInDays(days), expired: false };
}

const useLabel = (use: Use) => (use.kind === 'other' ? use.value : strings.useLabels[use.kind]);
const uses = (certificate: LocalCertificateView) =>
    certificate.uses.length === 0 ? strings.anyPurpose : certificate.uses.map(useLabel).join(', ');

function algorithm(key: KeyAlgorithm): string {
    switch (key.kind) {
        case 'rsa':
            return `RSA ${key.value.bits}`;
        case 'ec':
            return `ECDSA ${key.value.curve}`;
        case 'ed25519':
            return 'Ed25519';
        default:
            return key.value;
    }
}

const signInProblem = (problem: string) => strings.signInProblems[problem] ?? strings.otherSignInProblem(problem);

function fingerprintLines(fingerprint: string): string[] {
    const bytes = fingerprint.split(':');
    const lines: string[] = [];
    for (let at = 0; at < bytes.length; at += fingerprintLineBytes) {
        lines.push(bytes.slice(at, at + fingerprintLineBytes).join(':'));
    }
    return lines;
}

function Group({ title, children }: Readonly<{ title: string; children: ReactNode }>) {
    const id = useId();
    return (
        <section aria-labelledby={id} className="flex flex-col gap-s2">
            <h3 id={id} className="text-caption font-semibold text-secondary">
                {title}
            </h3>
            <dl className="grid grid-cols-[minmax(0,1fr)_minmax(0,2fr)] gap-x-s3 gap-y-s2 text-body">{children}</dl>
        </section>
    );
}

function Field({ label, children, bad = false }: Readonly<{ label: string; children: ReactNode; bad?: boolean }>) {
    return (
        <>
            <dt className="text-secondary">{label}</dt>
            <dd className={`break-all ${bad ? 'text-bad' : 'text-primary'}`}>{children}</dd>
        </>
    );
}

function Detail({ certificate, now }: Readonly<{ certificate: LocalCertificateView; now: number }>) {
    const state = status(certificate, now);
    return (
        <section aria-labelledby="certificate-title" className="flex min-w-0 flex-col gap-s4">
            <header className="flex flex-col gap-s1">
                <h2 id="certificate-title" className="text-title font-semibold text-primary">
                    {certificate.name}
                </h2>
                <p className={`text-caption ${state.expired ? 'text-bad' : 'text-secondary'}`}>{state.text}</p>
            </header>
            <Group title={strings.certificateGroupTitle}>
                <Field label={strings.validFrom}>{strings.date(certificate.notBefore)}</Field>
                <Field label={strings.validUntil}>{strings.date(certificate.notAfter)}</Field>
                <Field label={strings.issuer}>{certificate.issuerName}</Field>
                <Field label={strings.serial}>{certificate.serial}</Field>
            </Group>
            <Group title={strings.useGroupTitle}>
                <Field label={strings.allowedFor}>{uses(certificate)}</Field>
                <dt className="text-secondary">{strings.signInRow}</dt>
                <dd className={`break-words ${certificate.canSignIn ? 'text-fine' : 'text-bad'}`}>
                    {certificate.canSignIn ? strings.canSignInToIlm : signInProblem(certificate.signInProblem ?? '')}
                </dd>
            </Group>
            <Group title={strings.privateKeyGroupTitle}>
                <Field label={strings.location}>{strings.locationLabels[certificate.location]}</Field>
                <Field label={strings.algorithm}>{algorithm(certificate.key)}</Field>
            </Group>
            <Group title={strings.namesGroupTitle}>
                <Field label={strings.subject}>{certificate.subject}</Field>
                {certificate.alternativeNames.length > 0 && (
                    <Field label={strings.alternativeNames}>{certificate.alternativeNames.join(', ')}</Field>
                )}
            </Group>
            <section className="flex flex-col gap-s2">
                <h3 className="text-caption font-semibold text-secondary">{strings.fingerprintTitle}</h3>
                <p data-fingerprint className="select-text font-mono text-caption text-primary">
                    {fingerprintLines(certificate.fingerprint).map((line) => (
                        <span key={line} className="block">
                            {line}
                        </span>
                    ))}
                </p>
            </section>
        </section>
    );
}

const columns = 'grid grid-cols-[minmax(0,2fr)_minmax(0,1fr)_minmax(0,1.2fr)] items-center gap-x-s3 px-s3';

function List({
    items,
    selected,
    now,
    onSelect,
}: Readonly<{ items: LocalCertificateView[]; selected: number; now: number; onSelect: (index: number) => void }>) {
    const rows = useRef<(HTMLDivElement | null)[]>([]);

    const move = (event: KeyboardEvent, index: number) => {
        const last = items.length - 1;
        const target = { ArrowDown: Math.min(index + 1, last), ArrowUp: Math.max(index - 1, 0), Home: 0, End: last }[event.key];
        if (target !== undefined) {
            event.preventDefault();
            onSelect(target);
            rows.current[target]?.focus();
        }
    };

    return (
        <div className="flex min-w-0 flex-col gap-s1">
            <div aria-hidden className={`${columns} border-b border-separator pb-s2 text-caption font-semibold text-secondary`}>
                <span>{strings.certificateHeader}</span>
                <span>{strings.privateKeyHeader}</span>
                <span>{strings.statusHeader}</span>
            </div>
            <div role="listbox" aria-label={strings.certificatesListLabel} className="flex flex-col">
                {items.map((certificate, index) => {
                    const state = status(certificate, now);
                    return (
                        <div
                            key={certificate.fingerprint}
                            ref={(row) => {
                                rows.current[index] = row;
                            }}
                            role="option"
                            tabIndex={index === selected ? 0 : -1}
                            aria-selected={index === selected}
                            aria-label={`${certificate.name}, ${uses(certificate)}, ${strings.locationLabels[certificate.location]}, ${state.text}`}
                            onClick={() => onSelect(index)}
                            onKeyDown={(event) => move(event, index)}
                            className={`${columns} cursor-default rounded-control py-s2 hover:bg-row-hover aria-selected:bg-row-current motion-safe:transition-colors`}
                        >
                            <span className="flex min-w-0 flex-col">
                                <span className="text-body text-primary">{certificate.name}</span>
                                <span className="text-caption text-secondary">{uses(certificate)}</span>
                            </span>
                            <span className="text-body text-secondary">{strings.locationLabels[certificate.location]}</span>
                            <span className={`text-body ${state.expired ? 'text-bad' : 'text-secondary'}`}>{state.text}</span>
                        </div>
                    );
                })}
            </div>
        </div>
    );
}

/** The person's certificates that have a private key on this computer, with the detail of the selected one. */
export function Certificates() {
    const { platform } = useAppInfo();
    const system = platform === 'macos' ? 'macos' : 'windows';
    const [state, setState] = useState<State>({ kind: 'loading' });
    const [chosen, setChosen] = useState<string | null>(null);
    const latest = useRef(0);
    const lastAsked = useRef(0);
    const pending = useRef<ReturnType<typeof setTimeout> | null>(null);

    const request = useCallback(() => {
        const id = ++latest.current;
        lastAsked.current = Date.now();
        localCertificates().then(
            (items) => {
                if (id !== latest.current) {
                    return;
                }
                setState({ kind: 'ready', items });
                setChosen((current) =>
                    items.some((certificate) => certificate.fingerprint === current) ? current : (items[0]?.fingerprint ?? null),
                );
            },
            (error) => id === latest.current && setState({ kind: 'error', message: String(error) || strings.certificatesLoadFailed }),
        );
    }, []);

    useEffect(() => {
        request();
        const refresh = () => {
            if (document.visibilityState === 'hidden' || pending.current !== null) {
                return;
            }
            const wait = lastAsked.current + refreshEvery - Date.now();
            if (wait <= 0) {
                request();
                return;
            }
            pending.current = setTimeout(() => {
                pending.current = null;
                request();
            }, wait);
        };
        window.addEventListener('focus', refresh);
        document.addEventListener('visibilitychange', refresh);
        return () => {
            window.removeEventListener('focus', refresh);
            document.removeEventListener('visibilitychange', refresh);
            if (pending.current !== null) {
                clearTimeout(pending.current);
                pending.current = null;
            }
            latest.current += 1;
        };
    }, [request]);

    const items = state.kind === 'ready' ? state.items : [];
    const found = items.findIndex((certificate) => certificate.fingerprint === chosen);
    const selected = Math.max(found, 0);
    const now = Date.now();

    return (
        <div className="@container flex flex-col gap-s4">
            <header>
                <h1 className="text-large-title font-semibold text-primary">{strings.certificates}</h1>
                {state.kind === 'ready' && (
                    <p className="text-body text-secondary">{strings.certificatesOnThisComputer(items.length, system)}</p>
                )}
            </header>
            {state.kind === 'error' && (
                <div role="alert" className="flex flex-col items-start gap-s3 text-body text-bad">
                    <p>{state.message}</p>
                    <button
                        type="button"
                        onClick={request}
                        className="h-control rounded-control border border-button-edge bg-button px-s3 text-body text-primary"
                    >
                        {strings.tryAgain}
                    </button>
                </div>
            )}
            {state.kind === 'ready' && items.length === 0 && (
                <p className="text-body text-secondary">{strings.noLocalCertificates(system)}</p>
            )}
            {state.kind === 'ready' && items.length > 0 && (
                <div className="flex flex-col gap-s5 @3xl:flex-row">
                    <div className="min-w-0 flex-[3]">
                        <List
                            items={items}
                            selected={selected}
                            now={now}
                            onSelect={(index) => setChosen(items[index]?.fingerprint ?? null)}
                        />
                    </div>
                    <div className="min-w-0 flex-[2] border-t border-separator pt-s4 @3xl:border-t-0 @3xl:border-l @3xl:pt-0 @3xl:pl-s5">
                        {items[selected] && <Detail certificate={items[selected]} now={now} />}
                    </div>
                </div>
            )}
        </div>
    );
}
