import { useCallback, useEffect, useRef, useState } from 'react';
import { type FollowView, followRequest, renewNow, requestFailure, stopFollowingRequest } from './bridge';
import { strings } from './strings';

const followEvery = 2000;
const followTries = 30;

/** Where a renewal started here stands: `busy` while it is sent, `working` while ILM has it. */
export interface Progress {
    kind: 'busy' | 'working' | 'done' | 'failed';
    text: string;
}

/** How a followed renewal stands, and whether that is the end of it. */
function outcome(view: FollowView): { progress: Progress; settled: boolean } {
    switch (view.state) {
        case 'installed':
        case 'renewed':
            return { progress: { kind: 'done', text: strings.renewalDone }, settled: true };
        case 'ended':
            return {
                progress: { kind: 'failed', text: view.reason === 'rejected' ? strings.renewalRejected : strings.renewalNotIssued },
                settled: true,
            };
        case 'notInstalled':
            return { progress: { kind: 'failed', text: strings.renewalNotInstalled }, settled: true };
        case 'waiting':
            return {
                progress: {
                    kind: 'working',
                    text: view.stage === 'pendingApproval' ? strings.renewalWaitingForApproval : strings.renewalInProgress,
                },
                settled: false,
            };
        default:
            return { progress: { kind: 'working', text: strings.renewalInProgress }, settled: false };
    }
}

function refusal(error: unknown): string {
    const failure = requestFailure(error);
    if (failure.kind === 'message') {
        return failure.message || strings.renewalFailed;
    }
    return failure.kind === 'refused' && failure.messages.length > 0 ? failure.messages.join(' ') : strings.renewalFailed;
}

/** Renews a certificate now and follows the renewal until it is installed or ends; nothing is followed after unmount. */
export function useRenewNow(): { progress: Progress | null; renew: (fingerprint: string) => void } {
    const [progress, setProgress] = useState<Progress | null>(null);
    const alive = useRef(true);
    const timer = useRef<ReturnType<typeof setTimeout> | undefined>(undefined);
    const followed = useRef<string | null>(null);

    useEffect(() => {
        alive.current = true;
        return () => {
            alive.current = false;
            clearTimeout(timer.current);
            if (followed.current !== null) {
                stopFollowingRequest(followed.current).catch(() => undefined);
            }
        };
    }, []);

    const follow = useCallback((certificate: string, tries: number) => {
        const again = () => {
            if (!alive.current) {
                return;
            }
            if (tries + 1 < followTries) {
                timer.current = setTimeout(() => follow(certificate, tries + 1), followEvery);
            } else {
                followed.current = null;
                setProgress(null);
                stopFollowingRequest(certificate).catch(() => undefined);
            }
        };
        followRequest(certificate).then((view) => {
            if (!alive.current) {
                return;
            }
            const next = outcome(view);
            setProgress(next.progress);
            if (!next.settled) {
                again();
            } else {
                followed.current = null;
                stopFollowingRequest(certificate).catch(() => undefined);
            }
        }, again);
    }, []);

    const renew = useCallback(
        (fingerprint: string) => {
            setProgress({ kind: 'busy', text: strings.renewing });
            renewNow(fingerprint).then(
                (requested) => {
                    followed.current = requested.certificate;
                    if (alive.current) {
                        follow(requested.certificate, 0);
                    } else {
                        stopFollowingRequest(requested.certificate).catch(() => undefined);
                    }
                },
                (error) => alive.current && setProgress({ kind: 'failed', text: refusal(error) }),
            );
        },
        [follow],
    );

    return { progress, renew };
}

/** What a renewal started here says, under the control that started it. */
export function RenewStatus({ progress }: Readonly<{ progress: Progress | null }>) {
    if (progress === null || progress.kind === 'busy') {
        return null;
    }
    if (progress.kind === 'failed') {
        return (
            <p role="alert" className="text-caption text-bad">
                {progress.text}
            </p>
        );
    }
    return <output className="text-caption text-secondary">{progress.text}</output>;
}
