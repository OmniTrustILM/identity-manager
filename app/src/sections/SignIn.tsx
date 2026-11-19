import { type FormEvent, type ReactNode, useEffect, useId, useRef, useState } from 'react';
import {
    cancelSignIn,
    type CertificateChoice,
    certificates,
    connect,
    onSignInChoices,
    type ProviderChoice,
    reopenBrowser,
    type SessionView,
    signIn,
    signInAgain,
    signInWithCertificate,
    signOut,
} from '../bridge';
import { TextField } from '../components/TextField/TextField';
import { BusyIcon, LockIcon, ProblemIcon } from '../design-system/icons';
import { strings } from '../strings';

type Idle = Extract<SessionView, { state: 'signedOut' }>;
type Waiting = Extract<SessionView, { state: 'signingIn' }>;

// WebKit leaves buttons out of the Tab order unless they say so.
const primary = 'h-button w-full rounded-control bg-accent px-s3 text-body text-on-accent disabled:opacity-disabled';
const secondary = 'h-button w-full rounded-control border border-button-edge bg-button px-s3 text-body text-primary';
const plain = 'h-control rounded-control px-s3 text-body text-accent';

function useFirstFocus<T extends HTMLElement>() {
    const first = useRef<T>(null);
    useEffect(() => first.current?.focus(), []);
    return first;
}

function Problem({ id, children }: Readonly<{ id: string; children: ReactNode }>) {
    return (
        <p id={id} role="alert" className="flex items-center gap-s2 text-caption text-bad">
            <ProblemIcon aria-hidden className="size-icon shrink-0" />
            {children}
        </p>
    );
}

function Step({ title, hint, children }: Readonly<{ title: string; hint: ReactNode; children: ReactNode }>) {
    return (
        <main className="flex min-h-screen items-center justify-center bg-surface p-s5 in-data-[os=macos]:pt-titlebar">
            <div className="flex w-form flex-col gap-s4">
                <header className="flex flex-col items-center gap-s2 text-center">
                    <h1 className="text-large-title font-semibold text-primary">{title}</h1>
                    {hint && <div className="text-body text-secondary">{hint}</div>}
                </header>
                {children}
            </div>
        </main>
    );
}

const certificateId = 'certificate';

function reason(error: unknown): string {
    return String(error) || strings.connectFailed;
}

/** Connect and Welcome: the address, read-only when the organization sets it, and the step to the choice of provider. */
function Address({ view, onChoose }: Readonly<{ view: Idle; onChoose: (providers: ProviderChoice[]) => void }>) {
    const id = useId();
    const noteId = `${id}-note`;
    const problemId = `${id}-problem`;
    const field = useFirstFocus<HTMLInputElement>();
    const managed = view.locked && view.address !== null;
    const [address, setAddress] = useState(view.address ?? '');
    const [error, setError] = useState<string | null>(null);
    const [busy, setBusy] = useState(false);
    const shown = error ?? view.problem;

    const submit = async (event: FormEvent) => {
        event.preventDefault();
        setBusy(true);
        setError(null);
        try {
            const providers = await connect(address.trim());
            if (providers.length === 0) {
                setError(strings.connectFailed);
            } else if (providers.length === 1 && providers[0] && providers[0].id !== certificateId) {
                await signIn(providers[0].id);
            } else {
                onChoose(providers);
            }
        } catch (error_) {
            setError(reason(error_));
        } finally {
            setBusy(false);
        }
    };

    return (
        <Step title={managed ? strings.welcomeTitle : strings.connectTitle} hint={managed ? strings.welcomeHint : strings.connectHint}>
            <form onSubmit={submit} className="flex flex-col gap-s3">
                <div className="flex flex-col gap-s1">
                    <label htmlFor={id} className="text-caption text-secondary">
                        {strings.ilmAddress}
                    </label>
                    <div className="relative flex items-center">
                        <TextField
                            id={id}
                            ref={field}
                            value={address}
                            readOnly={managed}
                            aria-invalid={shown && !managed ? true : undefined}
                            aria-describedby={[managed && noteId, shown && problemId].filter(Boolean).join(' ') || undefined}
                            onChange={(event) => {
                                setAddress(event.target.value);
                                setError(null);
                            }}
                            className={managed ? 'pl-[calc(var(--spacing-s5)+var(--spacing-s2))]' : undefined}
                        />
                        {managed && <LockIcon aria-hidden className="pointer-events-none absolute left-s2 size-icon text-secondary" />}
                    </div>
                    {managed && (
                        <p id={noteId} className="text-caption text-secondary">
                            {strings.managedByOrganization}
                        </p>
                    )}
                    {shown && <Problem id={problemId}>{shown}</Problem>}
                </div>
                <button type="submit" tabIndex={0} disabled={busy || address.trim() === ''} aria-busy={busy} className={primary}>
                    {managed ? strings.signIn : strings.continue}
                </button>
            </form>
        </Step>
    );
}

/** A sign-in that ended without the person signing out: the reason, and one step to repeat it. */
function Ended({ view, onChoose }: Readonly<{ view: Idle; onChoose: (providers: ProviderChoice[]) => void }>) {
    const problemId = useId();
    const first = useFirstFocus<HTMLButtonElement>();
    const [error, setError] = useState<string | null>(null);

    const again = () => {
        setError(null);
        signInAgain().then(
            (providers) => providers.length > 0 && onChoose(providers),
            (error_) => setError(reason(error_)),
        );
    };

    return (
        <Step title={strings.signedOutTitle} hint={null}>
            <div className="flex flex-col gap-s3">
                <Problem id={problemId}>{error ?? view.problem ?? strings.signInEnded}</Problem>
                <button ref={first} type="button" tabIndex={0} aria-describedby={problemId} onClick={again} className={primary}>
                    {strings.signInAgain}
                </button>
            </div>
        </Step>
    );
}

/** The saved sign-in is kept while ILM cannot be reached; the person is told where and why, and can sign out. */
export function Unreachable({ view }: Readonly<{ view: Extract<SessionView, { state: 'unreachable' }> }>) {
    const problemId = useId();
    const first = useFirstFocus<HTMLButtonElement>();
    const [error, setError] = useState<string | null>(null);

    const leave = () => {
        setError(null);
        signOut().catch((error_) => setError(reason(error_)));
    };

    return (
        <Step title={strings.unreachableTitle} hint={view.address}>
            <div className="flex flex-col gap-s3">
                <Problem id={problemId}>{error ?? view.problem}</Problem>
                <button ref={first} type="button" tabIndex={0} aria-describedby={problemId} onClick={leave} className={plain}>
                    {strings.signOut}
                </button>
            </div>
        </Step>
    );
}

function Choice({
    providers,
    problem,
    onCertificate,
    onBack,
}: Readonly<{ providers: ProviderChoice[]; problem: string | null; onCertificate: () => void; onBack: () => void }>) {
    const problemId = useId();
    const first = useFirstFocus<HTMLButtonElement>();
    const [error, setError] = useState<string | null>(null);
    const shown = error ?? problem;

    return (
        <Step title={strings.chooseTitle} hint={strings.chooseHint}>
            <div className="flex flex-col gap-s3">
                {providers.map((provider, index) => (
                    <button
                        key={provider.id}
                        ref={index === 0 ? first : undefined}
                        type="button"
                        tabIndex={0}
                        aria-describedby={shown ? problemId : undefined}
                        onClick={() =>
                            provider.id === certificateId
                                ? onCertificate()
                                : signIn(provider.id).catch((error_) => setError(reason(error_)))
                        }
                        className={secondary}
                    >
                        {provider.name}
                    </button>
                ))}
                {shown && <Problem id={problemId}>{shown}</Problem>}
                <button type="button" tabIndex={0} onClick={onBack} className={`${plain} self-center`}>
                    {strings.back}
                </button>
            </div>
        </Step>
    );
}

const radio =
    'size-icon shrink-0 appearance-none rounded-full border border-switch-edge checked:border-accent checked:bg-accent checked:shadow-[inset_0_0_0_var(--spacing-s1)_var(--color-field)]';

function CertificateRow({ choice, checked, onSelect }: Readonly<{ choice: CertificateChoice; checked: boolean; onSelect: () => void }>) {
    return (
        <label className="grid cursor-pointer grid-cols-[auto_minmax(0,1fr)] items-center gap-x-s3 rounded-control border border-field-edge bg-card px-s3 py-s2 has-checked:border-accent has-checked:bg-button">
            <input type="radio" name="certificate" tabIndex={0} checked={checked} onChange={onSelect} className={`${radio} row-span-2`} />
            <span className="truncate text-body text-primary">{choice.subject}</span>
            <span className="truncate text-caption text-secondary">
                {choice.issuer} · {strings.certificateExpires(choice.notAfter)}
            </span>
        </label>
    );
}

/**
 * Choose certificate. One candidate signs in without asking, but only on the first visit: after an attempt that failed
 * the list shows again, with the reason, so that the person can retry or go back.
 */
function Certificates({ problem, automatic, onBack }: Readonly<{ problem: string | null; automatic: boolean; onBack: () => void }>) {
    const problemId = useId();
    const [choices, setChoices] = useState<CertificateChoice[] | null>(null);
    const [selected, setSelected] = useState<string | null>(null);
    const [error, setError] = useState<string | null>(null);
    const shown = error ?? problem;

    const signInWith = (fingerprint: string) => {
        setError(null);
        signInWithCertificate(fingerprint).catch((error_) => setError(reason(error_)));
    };

    useEffect(() => {
        let current = true;
        certificates().then(
            (found) => {
                if (!current) {
                    return;
                }
                setChoices(found);
                setSelected((found.find((choice) => choice.remembered) ?? found[0])?.fingerprint ?? null);
                if (automatic && found.length === 1 && found[0]) {
                    signInWithCertificate(found[0].fingerprint).catch((error_) => setError(reason(error_)));
                }
            },
            (error_) => current && setError(reason(error_)),
        );
        return () => {
            current = false;
        };
    }, [automatic]);

    return (
        <Step title={strings.certificateTitle} hint={strings.certificateHint}>
            <div className="flex flex-col gap-s3">
                {choices?.length === 0 && <Problem id={`${problemId}-none`}>{strings.noCertificate}</Problem>}
                {choices && choices.length > 0 && (
                    <div
                        role="radiogroup"
                        aria-label={strings.certificateGroup}
                        aria-describedby={shown ? problemId : undefined}
                        className="flex flex-col gap-s2"
                    >
                        {choices.map((choice) => (
                            <CertificateRow
                                key={choice.fingerprint}
                                choice={choice}
                                checked={choice.fingerprint === selected}
                                onSelect={() => setSelected(choice.fingerprint)}
                            />
                        ))}
                    </div>
                )}
                {shown && <Problem id={problemId}>{shown}</Problem>}
                <button
                    type="button"
                    tabIndex={0}
                    disabled={selected === null}
                    onClick={() => selected && signInWith(selected)}
                    className={primary}
                >
                    {strings.signIn}
                </button>
                <button type="button" tabIndex={0} onClick={onBack} className={`${plain} self-center`}>
                    {strings.back}
                </button>
            </div>
        </Step>
    );
}

function WaitingForCertificate() {
    const first = useFirstFocus<HTMLButtonElement>();
    return (
        <Step title={strings.certificateWaitingTitle} hint={strings.certificateWaitingHint}>
            <div className="flex flex-col items-center gap-s4">
                <output className="flex items-center gap-s2 text-body text-secondary">
                    <BusyIcon aria-hidden className="size-icon text-accent motion-safe:animate-spin" />
                    {strings.certificateWaitingStatus}
                </output>
                <button ref={first} type="button" tabIndex={0} onClick={() => cancelSignIn().catch(() => undefined)} className={plain}>
                    {strings.cancel}
                </button>
            </div>
        </Step>
    );
}

function Waiting({ view }: Readonly<{ view: Waiting }>) {
    const first = useFirstFocus<HTMLButtonElement>();
    if (view.method === 'certificate') {
        return <WaitingForCertificate />;
    }
    return (
        <Step title={strings.waitingTitle} hint={<output className="block">{strings.waitingHint(view.provider)}</output>}>
            <div className="flex flex-col items-center gap-s4">
                <button ref={first} type="button" tabIndex={0} onClick={() => reopenBrowser().catch(() => undefined)} className={secondary}>
                    {strings.openBrowserAgain}
                </button>
                <button type="button" tabIndex={0} onClick={() => cancelSignIn().catch(() => undefined)} className={plain}>
                    {strings.cancel}
                </button>
            </div>
        </Step>
    );
}

export function SignIn({ view }: Readonly<{ view: Idle | Waiting }>) {
    const [providers, setProviders] = useState<ProviderChoice[] | null>(null);
    const [picking, setPicking] = useState(false);
    // Only a problem from an attempt made from the choice belongs to it.
    const [tried, setTried] = useState(false);
    useEffect(() => {
        if (view.state === 'signingIn') {
            setTried(true);
        }
    }, [view.state]);

    useEffect(() => {
        // The tray can start a sign-in again, which hands the providers to this window.
        const listening = onSignInChoices(setProviders).catch(() => () => undefined);
        return () => {
            void listening.then((stop) => stop());
        };
    }, []);

    if (view.state === 'signingIn') {
        return <Waiting view={view} />;
    }
    const back = () => {
        setProviders(null);
        setPicking(false);
        setTried(false);
    };
    if (!providers) {
        return view.again ? <Ended view={view} onChoose={setProviders} /> : <Address view={view} onChoose={setProviders} />;
    }
    const onlyCertificate = providers.length === 1 && providers[0]?.id === certificateId;
    if (picking || onlyCertificate) {
        return (
            <Certificates
                problem={tried ? view.problem : null}
                automatic={!tried}
                onBack={onlyCertificate ? back : () => setPicking(false)}
            />
        );
    }
    return <Choice providers={providers} problem={tried ? view.problem : null} onCertificate={() => setPicking(true)} onBack={back} />;
}
