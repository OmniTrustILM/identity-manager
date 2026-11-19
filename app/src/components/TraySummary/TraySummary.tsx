import { type ReactNode, useCallback, useEffect, useLayoutEffect, useRef } from 'react';
import { useAppInfo } from '../../app-info';
import { hideSummary, openMainWindow, reportReady, type SessionView, signInAgain, unlock } from '../../bridge';
import { AppIcon, FineIcon, LockIcon, ProblemIcon, UnreachableIcon } from '../../design-system/icons';
import { useSession } from '../../session';
import { strings } from '../../strings';

const primary = 'h-control rounded-control bg-accent px-s3 text-body text-on-accent';
const secondary = 'h-control rounded-control border border-button-edge bg-button px-s3 text-body text-primary';

function hostOf(address: string): string {
    try {
        return new URL(address).host || address;
    } catch {
        return address;
    }
}

interface Line {
    icon: ReactNode;
    text: string;
    problem?: string;
}

/** The one line that says where the sign-in stands; nothing while it is starting or in progress. */
function lineFor(view: SessionView | null): Line | null {
    switch (view?.state) {
        case 'signedIn':
            return view.unreachable
                ? { icon: <UnreachableIcon className="text-attention" />, text: strings.summaryUnreachable(hostOf(view.address)) }
                : { icon: <FineIcon className="text-fine" />, text: strings.summarySignedIn(hostOf(view.address), view.person.name) };
        case 'unreachable':
            return { icon: <UnreachableIcon className="text-attention" />, text: strings.summaryUnreachable(hostOf(view.address)) };
        case 'signedOut':
            return {
                icon: <ProblemIcon className={view.problem ? 'text-bad' : 'text-secondary'} />,
                text: strings.signedOutTitle,
                problem: view.problem ?? undefined,
            };
        case 'locked':
            return { icon: <LockIcon className="text-secondary" />, text: strings.lockedTitle };
        default:
            return null;
    }
}

function actionFor(view: SessionView | null): { label: string; run: () => Promise<unknown> } | null {
    if (view?.state === 'locked') {
        return { label: strings.unlock, run: unlock };
    }
    if (view?.state === 'signedOut' && view.again) {
        return { label: strings.signInAgain, run: signInAgain };
    }
    return null;
}

export function TraySummary() {
    const info = useAppInfo();
    const { view } = useSession();
    const content = useRef<HTMLDivElement>(null);
    const line = lineFor(view);
    const action = actionFor(view);

    // The summary only renders when the session or the details change, and each time its height may differ.
    useLayoutEffect(() => {
        const height = Math.ceil(content.current?.getBoundingClientRect().height ?? 0);
        reportReady(height > 0 ? { ...info, height } : info).catch(() => undefined);
    });

    useEffect(() => {
        const hideOnEscape = (event: KeyboardEvent) => {
            if (event.key === 'Escape') {
                hideSummary().catch(() => undefined);
            }
        };
        document.addEventListener('keydown', hideOnEscape);
        return () => document.removeEventListener('keydown', hideOnEscape);
    }, []);

    // The first button is the one the person most likely wants; it takes focus whenever the summary shows or changes.
    const focusFirst = useCallback(() => content.current?.querySelector('button')?.focus(), []);
    useEffect(() => focusFirst());
    useEffect(() => {
        window.addEventListener('focus', focusFirst);
        return () => window.removeEventListener('focus', focusFirst);
    }, [focusFirst]);

    return (
        // The macOS window is transparent with a material of its own; elsewhere the summary paints its surface.
        <div className="min-h-screen w-tray bg-surface text-body text-primary in-data-[os=macos]:bg-transparent">
            <div ref={content} className="flex flex-col gap-s4 p-s4">
                <header className="flex items-center gap-s3">
                    <AppIcon aria-hidden className="size-icon shrink-0 text-accent" />
                    <div>
                        <h1 className="text-title">{info.name}</h1>
                        <p className="text-caption text-secondary">{strings.version(info.version)}</p>
                    </div>
                </header>
                {line && (
                    <div className="flex items-start gap-s2">
                        <span aria-hidden className="flex h-lh items-center [&>svg]:size-icon">
                            {line.icon}
                        </span>
                        <div>
                            <p>{line.text}</p>
                            {line.problem && <p className="text-caption text-bad">{line.problem}</p>}
                        </div>
                    </div>
                )}
                <div className="flex flex-col gap-s2">
                    {action && (
                        <button type="button" tabIndex={0} onClick={() => action.run().catch(() => undefined)} className={primary}>
                            {action.label}
                        </button>
                    )}
                    <button
                        type="button"
                        tabIndex={0}
                        onClick={() => openMainWindow().catch(() => undefined)}
                        className={action ? secondary : primary}
                    >
                        {strings.openApp}
                    </button>
                </div>
            </div>
        </div>
    );
}
