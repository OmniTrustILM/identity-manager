import { type ReactNode, useCallback, useEffect, useLayoutEffect, useRef } from 'react';
import { useAppInfo } from '../../app-info';
import { approvalDetail, attentionDetail, attentionLook, waitingDetail } from '../../attention';
import {
    type AttentionItemView,
    hideSummary,
    openMainWindow,
    reportReady,
    type SessionView,
    signInAgain,
    type SummaryView,
    unlock,
} from '../../bridge';
import { AppIcon, ChevronIcon, FineIcon, LockIcon, OfflineIcon, ProblemIcon, UnreachableIcon } from '../../design-system/icons';
import { useSession } from '../../session';
import { strings } from '../../strings';
import { useSummary } from '../../useSummary';

/** At most this many attention items are listed; the others are counted. */
const listed = 3;

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
    /** Said under the line in the colour of attention. */
    attention?: string;
}

/** The one line that says where the sign-in stands; nothing while it is starting or in progress. */
function lineFor(view: SessionView | null, needsAttention: boolean): Line | null {
    switch (view?.state) {
        case 'signedIn':
            if (view.unreachable) {
                return { icon: <UnreachableIcon className="text-attention" />, text: strings.summaryUnreachable(hostOf(view.address)) };
            }
            return {
                icon: needsAttention ? <ProblemIcon className="text-attention" /> : <FineIcon className="text-fine" />,
                text: strings.summarySignedIn(hostOf(view.address), view.person.name),
                attention: needsAttention ? strings.needsAttention : undefined,
            };
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

const isOffline = (view: SessionView | null) => view?.state === 'unreachable' || (view?.state === 'signedIn' && view.unreachable);

function Counts({ summary }: Readonly<{ summary: SummaryView }>) {
    const { valid, expiring, expired, notInIlm } = summary.counts;
    const counts: [number | null, string, string][] = [
        [valid, strings.valid, 'bg-fine'],
        [expiring, strings.expiringSoon, 'bg-attention'],
        [expired, strings.expired, 'bg-bad'],
        [notInIlm, strings.notInIlm, 'bg-wait'],
    ];
    return (
        <ul aria-label={strings.countsLabel} className="grid grid-flow-col auto-cols-fr gap-s2">
            {counts.map(([count, label, dot]) =>
                count === null ? null : (
                    <li key={label} className="flex flex-col">
                        <span className="flex items-center gap-s2 text-title">
                            <span aria-hidden className={`size-s2 shrink-0 rounded-full ${dot}`} />
                            {count}
                        </span>
                        <span className="text-caption text-secondary">{label}</span>
                    </li>
                ),
            )}
        </ul>
    );
}

function itemTitle(item: AttentionItemView): string {
    switch (item.kind) {
        case 'notInIlm':
            return strings.notInIlmCountShort(item.count);
        case 'waiting':
            return item.label;
        default:
            return item.name;
    }
}

const itemKey = (item: AttentionItemView) => {
    switch (item.kind) {
        case 'notInIlm':
            return item.kind;
        case 'waiting':
            return `${item.kind}:${item.label}`;
        case 'approval':
            return `${item.kind}:${item.name}`;
        default:
            return `${item.kind}:${item.fingerprint}`;
    }
};

/** What the main window is asked to show for an item: the certificate, the requests, or Overview. */
function target(item: AttentionItemView): string {
    if (item.kind === 'approval') {
        return 'requests';
    }
    return 'fingerprint' in item ? item.fingerprint : 'overview';
}

function Item({ item }: Readonly<{ item: AttentionItemView }>) {
    const { Icon, tone, textTone } = attentionLook(item);
    const certificate = item.kind === 'notInIlm' || item.kind === 'waiting' || item.kind === 'approval' ? null : item;
    return (
        <li>
            <button
                type="button"
                tabIndex={0}
                data-item
                onClick={() => openMainWindow(target(item)).catch(() => undefined)}
                className="flex w-full items-center gap-s3 rounded-control bg-row-hover px-s3 py-s2 text-left"
            >
                <Icon aria-hidden className={`size-icon shrink-0 ${tone}`} />
                <span className="flex min-w-0 flex-1 flex-col">
                    <span className="text-body text-primary">{itemTitle(item)}</span>
                    {certificate && <span className={`text-caption ${textTone}`}>{attentionDetail(certificate)}</span>}
                    {item.kind === 'waiting' && <span className={`text-caption ${textTone}`}>{waitingDetail(item)}</span>}
                    {item.kind === 'approval' && <span className={`text-caption ${textTone}`}>{approvalDetail(item)}</span>}
                </span>
                <ChevronIcon aria-hidden className="size-icon shrink-0 text-secondary" />
            </button>
        </li>
    );
}

/** The counts, the first items that need attention and when ILM was last checked. */
function Standing({ summary, offline, linux }: Readonly<{ summary: SummaryView; offline: boolean; linux: boolean }>) {
    const items = linux ? summary.attention.filter((item) => item.kind !== 'approval') : summary.attention;
    const more = items.length - listed;
    let note: string | null = null;
    if (offline) {
        note = summary.checkedAt === null ? strings.cannotReachIlm : strings.cannotReachIlmSince(summary.checkedAt);
    } else if (summary.checkedAt !== null) {
        note = strings.lastCheckedWithIlm(summary.checkedAt);
    }
    return (
        <>
            <Counts summary={summary} />
            {items.length > 0 && (
                <div className="flex flex-col gap-s1">
                    <ul className="flex flex-col gap-s1">
                        {items.slice(0, listed).map((item, index) => (
                            <Item key={`${itemKey(item)}:${index}`} item={item} />
                        ))}
                    </ul>
                    {more > 0 && <p className="px-s3 text-body text-secondary">{strings.moreAttention(more)}</p>}
                </div>
            )}
            {note !== null && (
                <p className="flex items-center gap-s2 text-caption text-secondary">
                    {offline && <OfflineIcon aria-hidden className="size-icon shrink-0" />}
                    {note}
                </p>
            )}
        </>
    );
}

export function TraySummary() {
    const info = useAppInfo();
    const { view } = useSession();
    const content = useRef<HTMLDivElement>(null);
    // Nothing about the certificates is asked, or shown, while the application is locked or nobody is signed in.
    const open = view?.state === 'signedIn' || view?.state === 'unreachable';
    const summary = useSummary(open);
    const line = lineFor(
        view,
        summary?.attention.some((item) => item.kind !== 'notInIlm' && item.kind !== 'waiting' && item.kind !== 'approval') ?? false,
    );
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
    const focusFirst = useCallback(() => content.current?.querySelector<HTMLElement>('button:not([data-item])')?.focus(), []);
    // A new summary re-renders the content; an item the person moved to keeps the focus.
    useEffect(() => {
        if (!(document.activeElement instanceof HTMLElement && document.activeElement.dataset.item)) focusFirst();
    });
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
                            {line.attention && <p className="text-caption text-attention-text">{line.attention}</p>}
                        </div>
                    </div>
                )}
                {open && summary && <Standing summary={summary} offline={isOffline(view)} linux={info.platform === 'linux'} />}
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
