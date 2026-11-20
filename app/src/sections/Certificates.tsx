import { type KeyboardEvent, useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { useAppInfo } from '../app-info';
import {
    type IlmCertificateView,
    type InventoryView,
    type KeyAlgorithm,
    type LocalCertificateView,
    localCertificates,
    makeSignInCertificate,
    type Use,
} from '../bridge';
import { ConfirmDialog } from '../components/ConfirmDialog/ConfirmDialog';
import { InIlmIcon, ManagedIcon, NotInIlmIcon, OfflineIcon, SignInKeyIcon, SyncIcon } from '../design-system/icons';
import { strings } from '../strings';
import { useInventory } from '../useInventory';
import { arrowTarget, codeLabel, Field, FingerprintGroup, Group, status, validationTone } from './certificateParts';
import { IlmCertificates } from './IlmCertificates';

/** At most one request this often when the window comes back; the request the first answer needs is not delayed. */
const refreshEvery = 2000;

type State = { kind: 'loading' } | { kind: 'ready'; items: LocalCertificateView[] } | { kind: 'error'; message: string };
type System = 'macos' | 'windows';

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

type Match = IlmCertificateView | undefined;

/** Whether the last check looked this certificate up in ILM, so that having no match means it is not there. */
const lookedUp = (inventory: InventoryView | null, fingerprint: string) =>
    inventory?.listed === true && inventory.checked.includes(fingerprint);

/** What ILM knows of a local certificate, in two or three words; none before the first check. */
const ilmWord = (match: Match) => {
    if (!match) {
        return strings.notInIlm;
    }
    return match.raProfile ? strings.managedByIlm : strings.inIlm;
};

function IlmLine({ match }: Readonly<{ match: Match }>) {
    const Icon = match?.raProfile ? ManagedIcon : match ? InIlmIcon : NotInIlmIcon;
    const tone = match?.raProfile ? 'text-fine' : match ? 'text-secondary' : 'text-tertiary';
    return (
        <span
            title={match?.raProfile ? strings.managedThrough(match.raProfile.name) : undefined}
            className={`flex items-center gap-s1 text-caption ${tone}`}
        >
            <Icon aria-hidden className="size-[13px] shrink-0" />
            {ilmWord(match)}
        </span>
    );
}

function SignInMark() {
    return (
        <span role="img" aria-label={strings.signInCertificate} title={strings.signInCertificate} className="text-accent">
            <SignInKeyIcon aria-hidden className="size-icon shrink-0" />
        </span>
    );
}

const signInProblem = (problem: string) => strings.signInProblems[problem] ?? strings.otherSignInProblem(problem);

const primaryButton = 'h-button self-start rounded-control bg-accent px-s3 text-body text-on-accent';

/** The button that makes a certificate ILM knows the person's sign-in certificate, after a question. */
function SignInAction({
    certificate,
    match,
    inventory,
    system,
    apply,
}: Readonly<{
    certificate: LocalCertificateView;
    match: Match;
    inventory: InventoryView;
    system: System;
    apply: (view: InventoryView) => void;
}>) {
    const [confirming, setConfirming] = useState(false);
    const [busy, setBusy] = useState(false);
    const [problem, setProblem] = useState<string | null>(null);
    const allowed =
        match?.state === 'issued' &&
        !match.archived &&
        certificate.canSignIn &&
        inventory.status.state !== 'offline' &&
        inventory.signIn !== certificate.fingerprint;
    if (!allowed) {
        return null;
    }
    const current = inventory.signIn === null ? null : (inventory.matches[inventory.signIn]?.name ?? strings.currentSignInCertificate);

    const confirm = () => {
        setBusy(true);
        setProblem(null);
        makeSignInCertificate(certificate.fingerprint)
            .then(apply, (error) => setProblem(String(error) || strings.signInChangeFailed))
            .finally(() => {
                setBusy(false);
                setConfirming(false);
            });
    };

    return (
        <div className="flex flex-col gap-s2">
            <button tabIndex={0} type="button" onClick={() => setConfirming(true)} className={primaryButton}>
                {strings.makeSignInCertificate}
            </button>
            {problem !== null && (
                <p role="alert" className="text-caption text-bad">
                    {problem}
                </p>
            )}
            {confirming && (
                <ConfirmDialog
                    title={strings.signInQuestion(certificate.name)}
                    confirmLabel={strings.useThisCertificate}
                    busy={busy}
                    macos={system === 'macos'}
                    onConfirm={confirm}
                    onCancel={() => setConfirming(false)}
                >
                    {current !== null && strings.stopsWorking(current)}
                </ConfirmDialog>
            )}
        </div>
    );
}

function IlmGroup({ match, signIn }: Readonly<{ match: Match; signIn: boolean }>) {
    if (!match) {
        return (
            <Group title={strings.inIlmGroupTitle}>
                <Field label={strings.stateRow}>{strings.notInIlm}</Field>
            </Group>
        );
    }
    return (
        <Group title={strings.inIlmGroupTitle}>
            <Field label={strings.stateRow}>{codeLabel(match.state)}</Field>
            <Field label={strings.validationRow} tone={validationTone(match.validationStatus)}>
                {codeLabel(match.validationStatus)}
            </Field>
            <Field label={strings.managementRow}>
                {match.raProfile ? strings.managedThrough(match.raProfile.name) : strings.inIlmNotManaged}
            </Field>
            {match.owner !== null && <Field label={strings.ownerRow}>{match.owner}</Field>}
            {signIn && <Field label={strings.signInRow}>{strings.yourSignInCertificate}</Field>}
        </Group>
    );
}

function Detail({
    certificate,
    now,
    inventory,
    system,
    apply,
}: Readonly<{
    certificate: LocalCertificateView;
    now: number;
    inventory: InventoryView | null;
    system: System;
    apply: (view: InventoryView) => void;
}>) {
    const state = status(certificate, now);
    const known = lookedUp(inventory, certificate.fingerprint);
    const match = inventory?.matches[certificate.fingerprint];
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
            {known && <IlmGroup match={match} signIn={inventory?.signIn === certificate.fingerprint} />}
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
            <FingerprintGroup fingerprint={certificate.fingerprint} />
            {known && inventory && (
                <SignInAction
                    key={certificate.fingerprint}
                    certificate={certificate}
                    match={match}
                    inventory={inventory}
                    system={system}
                    apply={apply}
                />
            )}
        </section>
    );
}

const columns = 'grid grid-cols-[minmax(0,2fr)_minmax(0,1fr)_minmax(0,1.2fr)] items-center gap-x-s3 px-s3';

function List({
    items,
    selected,
    now,
    inventory,
    onSelect,
}: Readonly<{
    items: LocalCertificateView[];
    selected: number;
    now: number;
    inventory: InventoryView | null;
    onSelect: (index: number) => void;
}>) {
    const rows = useRef<(HTMLDivElement | null)[]>([]);

    const move = (event: KeyboardEvent, index: number) => {
        const target = arrowTarget(event.key, index, items.length - 1);
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
                    const match = inventory?.matches[certificate.fingerprint];
                    const known = lookedUp(inventory, certificate.fingerprint);
                    const signIn = known && inventory?.signIn === certificate.fingerprint;
                    const label = [
                        certificate.name,
                        uses(certificate),
                        strings.locationLabels[certificate.location],
                        state.text,
                        known ? ilmWord(match) : null,
                        signIn ? strings.signInCertificate : null,
                    ]
                        .filter((part) => part)
                        .join(', ');
                    return (
                        <div
                            key={certificate.fingerprint}
                            ref={(row) => {
                                rows.current[index] = row;
                            }}
                            role="option"
                            tabIndex={index === selected ? 0 : -1}
                            aria-selected={index === selected}
                            aria-label={label}
                            onClick={() => onSelect(index)}
                            onKeyDown={(event) => move(event, index)}
                            className={`${columns} cursor-default rounded-control py-s2 hover:bg-row-hover aria-selected:bg-row-current motion-safe:transition-colors`}
                        >
                            <span className="flex min-w-0 flex-col">
                                <span className="flex items-center gap-s1 text-body text-primary">
                                    {certificate.name}
                                    {signIn && <SignInMark />}
                                </span>
                                <span className="text-caption text-secondary">{uses(certificate)}</span>
                            </span>
                            <span className="text-body text-secondary">{strings.locationLabels[certificate.location]}</span>
                            <div className="flex flex-col">
                                <span className={`text-body ${state.expired ? 'text-bad' : 'text-secondary'}`}>{state.text}</span>
                                {known && <IlmLine match={match} />}
                            </div>
                        </div>
                    );
                })}
            </div>
        </div>
    );
}

function Views({ view, onChoose, system }: Readonly<{ view: View; onChoose: (view: View) => void; system: System }>) {
    const choices: [View, string][] = [
        ['local', strings.onThisComputer(system)],
        ['ilm', strings.inIlm],
    ];
    return (
        <fieldset className="flex shrink-0 gap-s1 rounded-control border border-button-edge bg-button p-s1">
            <legend className="sr-only">{strings.viewLabel}</legend>
            {choices.map(([id, label]) => (
                <button
                    tabIndex={0}
                    key={id}
                    type="button"
                    aria-pressed={view === id}
                    onClick={() => onChoose(id)}
                    className="h-control rounded-control px-s3 text-body text-secondary aria-pressed:bg-surface aria-pressed:text-primary"
                >
                    {label}
                </button>
            ))}
        </fieldset>
    );
}

function SyncLine({ inventory, onSync }: Readonly<{ inventory: InventoryView; onSync: () => void }>) {
    const { checking } = inventory;
    const stateOf = inventory.status;
    let note: string | null = null;
    if (checking) {
        note = strings.checkingIlm;
    } else if (stateOf.state === 'fresh') {
        note = strings.checkedWithIlm(stateOf.checkedAt);
    } else if (stateOf.state === 'offline') {
        note = stateOf.since === null ? strings.cannotReachIlm : strings.cannotReachIlmSince(stateOf.since);
    }
    return (
        <p className="flex items-center gap-s2 text-caption text-secondary">
            {!checking && stateOf.state === 'offline' && <OfflineIcon aria-hidden className="size-icon shrink-0" />}
            {note !== null && <output>{note}</output>}
            <button
                tabIndex={0}
                type="button"
                aria-label={strings.syncNow}
                title={strings.syncNow}
                disabled={checking}
                onClick={onSync}
                className="flex size-control items-center justify-center rounded-control border border-button-edge bg-button text-primary disabled:opacity-disabled"
            >
                <SyncIcon aria-hidden className={`size-icon ${checking ? 'motion-safe:animate-spin' : ''}`} />
            </button>
        </p>
    );
}

type View = 'local' | 'ilm';

/** The person's certificates that have a private key on this computer, with the detail of the selected one. */
export function Certificates() {
    const { platform } = useAppInfo();
    const system: System = platform === 'macos' ? 'macos' : 'windows';
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

    const { inventory, syncError, sync, apply } = useInventory();
    const [view, setView] = useState<View>('local');
    const [ilmTotal, setIlmTotal] = useState<number | null>(null);

    const items = state.kind === 'ready' ? state.items : [];
    const found = items.findIndex((certificate) => certificate.fingerprint === chosen);
    const selected = Math.max(found, 0);
    const now = Date.now();
    const listed = inventory?.listed === true;
    const known = listed && inventory.checkedAt !== null;
    const showing = listed ? view : 'local';
    const local = useMemo(() => new Set(items.map((certificate) => certificate.fingerprint)), [items]);
    const inIlm = items.filter((certificate) => inventory?.matches[certificate.fingerprint]).length;

    let subline: string | null = null;
    if (showing === 'ilm') {
        subline = ilmTotal === null ? null : strings.certificatesInIlmCount(ilmTotal);
    } else if (state.kind === 'ready') {
        subline = known ? strings.certificatesInIlm(items.length, inIlm, system) : strings.certificatesOnThisComputer(items.length, system);
    }

    return (
        <div className="@container flex flex-col gap-s4">
            <header className="flex items-start justify-between gap-s4">
                <div className="flex min-w-0 flex-col gap-s1">
                    <h1 className="text-large-title font-semibold text-primary">{strings.certificates}</h1>
                    {subline !== null && <p className="text-body text-secondary">{subline}</p>}
                    {listed && inventory && <SyncLine inventory={inventory} onSync={sync} />}
                    {syncError !== null && (
                        <p role="alert" className="text-caption text-bad">
                            {syncError}
                        </p>
                    )}
                </div>
                {listed && <Views view={showing} onChoose={setView} system={system} />}
            </header>
            {showing === 'ilm' && inventory && (
                <IlmCertificates inventory={inventory} local={local} system={system} onTotal={setIlmTotal} />
            )}
            {showing === 'local' && state.kind === 'error' && (
                <div role="alert" className="flex flex-col items-start gap-s3 text-body text-bad">
                    <p>{state.message}</p>
                    <button
                        tabIndex={0}
                        type="button"
                        onClick={request}
                        className="h-control rounded-control border border-button-edge bg-button px-s3 text-body text-primary"
                    >
                        {strings.tryAgain}
                    </button>
                </div>
            )}
            {showing === 'local' && state.kind === 'ready' && items.length === 0 && (
                <p className="text-body text-secondary">{strings.noLocalCertificates(system)}</p>
            )}
            {showing === 'local' && state.kind === 'ready' && items.length > 0 && (
                <div className="flex flex-col gap-s5 @3xl:flex-row">
                    <div className="min-w-0 flex-[3]">
                        <List
                            items={items}
                            selected={selected}
                            now={now}
                            inventory={inventory}
                            onSelect={(index) => setChosen(items[index]?.fingerprint ?? null)}
                        />
                    </div>
                    <div className="min-w-0 flex-[2] border-t border-separator pt-s4 @3xl:border-t-0 @3xl:border-l @3xl:pt-0 @3xl:pl-s5">
                        {items[selected] && (
                            <Detail certificate={items[selected]} now={now} inventory={inventory} system={system} apply={apply} />
                        )}
                    </div>
                </div>
            )}
        </div>
    );
}
