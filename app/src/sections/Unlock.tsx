import { useCallback, useEffect, useRef, useState } from 'react';
import { unlock } from '../bridge';
import { AppIcon, ProblemIcon } from '../design-system/icons';
import { strings } from '../strings';

/**
 * What a window shows while the application is locked. With `automatic` it asks the system to confirm the person as it
 * opens and each time the window is shown again; the button asks again after a refusal.
 */
export function Unlock({ automatic }: Readonly<{ automatic: boolean }>) {
    const [problem, setProblem] = useState<string | null>(null);
    const [busy, setBusy] = useState(false);
    const asking = useRef(false);
    const button = useRef<HTMLButtonElement>(null);

    const ask = useCallback(() => {
        if (asking.current) {
            return;
        }
        asking.current = true;
        setBusy(true);
        setProblem(null);
        unlock()
            .catch((error) => setProblem(String(error) || strings.unlockFailed))
            .finally(() => {
                asking.current = false;
                setBusy(false);
            });
    }, []);

    useEffect(() => {
        button.current?.focus();
        if (!automatic) {
            return;
        }
        // Focus also returns to the window when the system's prompt closes, so only becoming visible counts as a show.
        const askWhenShown = () => document.visibilityState === 'visible' && ask();
        askWhenShown();
        document.addEventListener('visibilitychange', askWhenShown);
        return () => document.removeEventListener('visibilitychange', askWhenShown);
    }, [automatic, ask]);

    return (
        <main className="flex min-h-screen items-center justify-center bg-surface p-s5 in-data-[os=macos]:pt-titlebar">
            <div className="flex w-form flex-col items-center gap-s4">
                <span className="flex size-[calc(var(--spacing-s5)*3)] items-center justify-center rounded-window bg-accent text-on-accent">
                    <AppIcon aria-hidden className="size-[calc(var(--spacing-s5)*1.5)]" />
                </span>
                <h1 className="text-center text-large-title font-semibold text-primary">{strings.lockedTitle}</h1>
                <div className="flex w-full flex-col gap-s3">
                    <button
                        ref={button}
                        type="button"
                        tabIndex={0}
                        aria-busy={busy}
                        onClick={ask}
                        className="h-button w-full rounded-control bg-accent px-s3 text-body text-on-accent"
                    >
                        {strings.unlock}
                    </button>
                    {problem && (
                        <p role="alert" className="flex items-center justify-center gap-s2 text-caption text-bad">
                            <ProblemIcon aria-hidden className="size-icon shrink-0" />
                            {problem}
                        </p>
                    )}
                </div>
            </div>
        </main>
    );
}
