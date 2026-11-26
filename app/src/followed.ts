import { useCallback, useEffect, useRef, useState } from 'react';
import { type FollowView, followRequest, requestFailure, stopFollowingRequest } from './bridge';

const followEvery = 2000;
const followTries = 30;

/** Where a request started here stands: `busy` while it is sent, `working` while ILM has it. */
export interface Progress {
    kind: 'busy' | 'working' | 'done' | 'failed';
    text: string;
}

/** How a followed request stands, and whether that is the end of it. */
export interface Outcome {
    progress: Progress;
    settled: boolean;
}

/** What a refused or failed request says: ILM's own words, else `fallback`. */
export function refusal(error: unknown, fallback: string): string {
    const failure = requestFailure(error);
    if (failure.kind === 'message') {
        return failure.message || fallback;
    }
    return failure.kind === 'refused' && failure.messages.length > 0 ? failure.messages.join(' ') : fallback;
}

/**
 * Follows a request ILM took every two seconds until `outcome` settles it, it gives up after thirty tries,
 * or the screen is left; the app is then told to stop following. The caller sets the first `progress`.
 */
export function useFollowedRequest(outcome: (view: FollowView) => Outcome) {
    const [progress, setProgress] = useState<Progress | null>(null);
    const alive = useRef(true);
    const timer = useRef<ReturnType<typeof setTimeout> | undefined>(undefined);
    const followed = useRef<string | null>(null);
    const settle = useRef(outcome);
    settle.current = outcome;

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

    const poll = useCallback((certificate: string, tries: number) => {
        const again = () => {
            if (!alive.current) {
                return;
            }
            if (tries + 1 < followTries) {
                timer.current = setTimeout(() => poll(certificate, tries + 1), followEvery);
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
            const next = settle.current(view);
            setProgress(next.progress);
            if (!next.settled) {
                again();
            } else {
                followed.current = null;
                stopFollowingRequest(certificate).catch(() => undefined);
            }
        }, again);
    }, []);

    const follow = useCallback(
        (certificate: string) => {
            followed.current = certificate;
            if (alive.current) {
                poll(certificate, 0);
            } else {
                stopFollowingRequest(certificate).catch(() => undefined);
            }
        },
        [poll],
    );

    return { progress, setProgress, follow };
}
