import { useId, useState } from 'react';
import {
    type FollowView,
    type KeyLocation,
    type LocalCertificateView,
    type RenewalView,
    type RevokeReason,
    type RevokingStage,
    revokeCertificate,
} from '../bridge';
import { ConfirmDialog } from '../components/ConfirmDialog/ConfirmDialog';
import { Select } from '../components/Switch/Select';
import { type Outcome, type Progress, refusal, useFollowedRequest } from '../followed';
import { RenewStatus } from '../renewNow';
import { strings } from '../strings';

type System = 'macos' | 'windows';

const reasons = Object.keys(strings.revokeReasons) as RevokeReason[];
const secondaryButton =
    'h-button self-start rounded-control border border-button-edge bg-button px-s3 text-body text-bad disabled:opacity-disabled';

/**
 * The text of the checkbox that removes the certificate too; none where it cannot be removed, as a smart-card
 * certificate on macOS, which is on the card only.
 */
function removeLabel(location: KeyLocation, system: System): string | null {
    switch (location) {
        case 'keychain':
        case 'software':
        case 'tpm':
            return strings.revokeDeleteWithKey(system);
        case 'smartCard':
            return system === 'windows' ? strings.revokeRemoveFromComputer : null;
        default:
            return null;
    }
}

/** What ILM is doing with a revocation that is not finished. */
function revoking(stage: RevokingStage): Progress {
    return { kind: 'working', text: stage === 'pendingApproval' ? strings.revokePendingApproval : strings.revoking };
}

/** How a followed revocation stands, and whether that is the end of it. */
function outcome(view: FollowView, removed: boolean): Outcome {
    switch (view.state) {
        case 'revoked':
            return { progress: { kind: 'done', text: removed ? strings.revokeDoneRemoved : strings.revokeDone }, settled: true };
        case 'notRevoked':
            return { progress: { kind: 'failed', text: strings.revokeNotRevoked }, settled: true };
        default:
            return { progress: revoking(view.state === 'revoking' ? view.stage : 'beingRevoked'), settled: false };
    }
}

/**
 * Revoke…, after a question about the reason and, where it can be removed, about removing it; then follows the
 * revocation. A revocation still waiting is told from `renewal` when the follow tells nothing, as after a reload.
 * How a followed revocation ended stays shown after ILM no longer lets the person revoke the certificate.
 */
export function RevokeAction({
    certificate,
    system,
    renewal,
}: Readonly<{ certificate: LocalCertificateView; system: System; renewal: RenewalView | undefined }>) {
    const reasonId = useId();
    const [confirming, setConfirming] = useState(false);
    const [sending, setSending] = useState(false);
    const [problem, setProblem] = useState<string | null>(null);
    const [reason, setReason] = useState<RevokeReason>('cessationOfOperation');
    const [ticked, setTicked] = useState(false);
    const checkbox = removeLabel(certificate.location, system);
    const remove = checkbox !== null && ticked;
    const { progress, setProgress, follow } = useFollowedRequest((view) => outcome(view, remove));

    const waiting = renewal?.revoking ?? null;
    const shown = progress ?? (waiting === null ? null : revoking(waiting));
    const canRevoke = renewal?.canRevoke ?? false;

    const confirm = () => {
        setSending(true);
        setProblem(null);
        revokeCertificate(certificate.fingerprint, reason, remove)
            .then(
                (requested) => {
                    setProgress(revoking('beingRevoked'));
                    setConfirming(false);
                    follow(requested.certificate);
                },
                (error) => setProblem(refusal(error, strings.revokeFailed)),
            )
            .finally(() => setSending(false));
    };

    if (!canRevoke && shown === null) {
        return null;
    }

    return (
        <div className="flex flex-col gap-s2">
            {(canRevoke || waiting !== null) && (
                <button
                    tabIndex={0}
                    type="button"
                    disabled={shown?.kind === 'working' || shown?.kind === 'done'}
                    onClick={() => setConfirming(true)}
                    className={secondaryButton}
                >
                    {strings.revoke}
                </button>
            )}
            <RenewStatus progress={shown} />
            {confirming && (
                <ConfirmDialog
                    title={strings.revokeQuestion(certificate.name)}
                    confirmLabel={strings.revokeConfirm}
                    destructive
                    busy={sending}
                    macos={system === 'macos'}
                    onConfirm={confirm}
                    onCancel={() => setConfirming(false)}
                    extra={
                        <>
                            <div className="flex flex-col gap-s1">
                                <label htmlFor={reasonId} className="text-caption text-secondary">
                                    {strings.revokeReasonLabel}
                                </label>
                                <Select
                                    id={reasonId}
                                    tabIndex={0}
                                    fill
                                    value={reason}
                                    options={reasons}
                                    label={(option) => strings.revokeReasons[option]}
                                    disabled={sending}
                                    onChange={setReason}
                                />
                            </div>
                            {checkbox !== null && (
                                <label className="flex items-start gap-s2 text-body text-primary">
                                    <input
                                        type="checkbox"
                                        tabIndex={0}
                                        checked={ticked}
                                        disabled={sending}
                                        onChange={(event) => setTicked(event.target.checked)}
                                        className="mt-[3px] size-icon shrink-0 accent-accent"
                                    />
                                    {checkbox}
                                </label>
                            )}
                            {problem !== null && (
                                <p role="alert" className="text-caption text-bad">
                                    {problem}
                                </p>
                            )}
                        </>
                    }
                >
                    {strings.revokeMessage}
                </ConfirmDialog>
            )}
        </div>
    );
}
