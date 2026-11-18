import { type FormEvent, type ReactNode, useEffect, useId, useRef, useState } from 'react';
import { cancelSignIn, connect, type ProviderChoice, reopenBrowser, type SessionView, signIn } from '../bridge';
import { TextField } from '../components/TextField/TextField';
import { LockIcon, ProblemIcon } from '../design-system/icons';
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
                    <div className="text-body text-secondary">{hint}</div>
                </header>
                {children}
            </div>
        </main>
    );
}

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
            } else if (providers.length === 1 && providers[0]) {
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

function Choice({ providers, problem, onBack }: Readonly<{ providers: ProviderChoice[]; problem: string | null; onBack: () => void }>) {
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
                        onClick={() => signIn(provider.id).catch((error_) => setError(reason(error_)))}
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

function Waiting({ view }: Readonly<{ view: Waiting }>) {
    const first = useFirstFocus<HTMLButtonElement>();
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
    // Only a problem from an attempt made from the choice belongs to it.
    const [tried, setTried] = useState(false);
    useEffect(() => {
        if (view.state === 'signingIn') {
            setTried(true);
        }
    }, [view.state]);

    if (view.state === 'signingIn') {
        return <Waiting view={view} />;
    }
    const back = () => {
        setProviders(null);
        setTried(false);
    };
    return providers ? (
        <Choice providers={providers} problem={tried ? view.problem : null} onBack={back} />
    ) : (
        <Address view={view} onChoose={setProviders} />
    );
}
