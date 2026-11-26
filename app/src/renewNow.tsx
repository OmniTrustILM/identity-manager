import { useCallback } from 'react';
import { type FollowView, renewNow } from './bridge';
import { type Outcome, type Progress, refusal, useFollowedRequest } from './followed';
import { strings } from './strings';

/** How a followed renewal stands, and whether that is the end of it. */
function outcome(view: FollowView): Outcome {
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

/** Renews a certificate now and follows the renewal until it is installed or ends; nothing is followed after unmount. */
export function useRenewNow(): { progress: Progress | null; renew: (fingerprint: string) => void } {
    const { progress, setProgress, follow } = useFollowedRequest(outcome);

    const renew = useCallback(
        (fingerprint: string) => {
            setProgress({ kind: 'busy', text: strings.renewing });
            renewNow(fingerprint).then(
                (requested) => follow(requested.certificate),
                (error) => setProgress({ kind: 'failed', text: refusal(error, strings.renewalFailed) }),
            );
        },
        [follow, setProgress],
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
