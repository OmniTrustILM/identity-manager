import { useEffect, useId, useState } from 'react';
import { type ApprovalDecision, type ApprovalFailure, type ApprovalView, approvalFailure, decideApproval } from '../bridge';
import { ConfirmDialog } from '../components/ConfirmDialog/ConfirmDialog';
import { areaClass } from '../components/AttributeForm/Field';
import { strings } from '../strings';
import { Group, row } from './Group';

const rowButton = 'h-control shrink-0 rounded-control px-s3 text-body disabled:opacity-disabled';
const approveButton = `${rowButton} bg-accent text-on-accent`;
const rejectButton = `${rowButton} border border-button-edge bg-button text-primary`;

/** What a failed decision says to the person. */
export function approvalProblem(failure: ApprovalFailure): string {
    switch (failure.kind) {
        case 'noLongerWaiting':
            return strings.approvalNoLongerWaiting;
        case 'refused':
            return failure.messages.join(' ');
        default:
            return failure.message || strings.approvalFailed;
    }
}

const nameOf = (approval: ApprovalView) => approval.certificateName ?? strings.approvalCertificate;

function RejectDialog({
    approval,
    busy,
    problem,
    macos,
    onReject,
    onCancel,
}: Readonly<{
    approval: ApprovalView;
    busy: boolean;
    problem: string | null;
    macos: boolean;
    onReject: (comment: string | null) => void;
    onCancel: () => void;
}>) {
    const [comment, setComment] = useState('');
    const hint = useId();
    const text = strings.rejectText(approval.requester, strings.approvalKindsAsked[approval.action], approval.raProfileName);
    const field = (
        <>
            <label className="flex flex-col gap-s1 text-caption font-semibold text-primary">
                {strings.rejectComment}
                <textarea
                    rows={3}
                    value={comment}
                    disabled={busy}
                    aria-describedby={hint}
                    onChange={(event) => setComment(event.target.value)}
                    className={`${areaClass} font-normal`}
                />
            </label>
            <p id={hint} className="text-caption text-secondary">
                {strings.rejectCommentHint}
            </p>
            {problem !== null && (
                <p role="alert" className="text-caption text-bad">
                    {problem}
                </p>
            )}
        </>
    );
    return (
        <ConfirmDialog
            title={strings.rejectTitle(nameOf(approval))}
            confirmLabel={strings.reject}
            busy={busy}
            macos={macos}
            extra={field}
            onConfirm={() => onReject(comment.trim() === '' ? null : comment)}
            onCancel={onCancel}
        >
            {text}
        </ConfirmDialog>
    );
}

function ApprovalRow({
    approval,
    busy,
    onApprove,
    onReject,
}: Readonly<{ approval: ApprovalView; busy: boolean; onApprove: () => void; onReject: () => void }>) {
    const name = nameOf(approval);
    return (
        <li className={row}>
            <div className="flex min-w-0 flex-1 flex-col">
                <span className="text-body text-primary">{name}</span>
                <span className="text-caption text-secondary">{strings.approvalFrom(approval.requester, approval.raProfileName)}</span>
            </div>
            <span className="min-w-0 flex-1 text-body text-secondary">
                {strings.approvalStatus(strings.approvalKinds[approval.action], approval.requestedAt)}
            </span>
            <button type="button" aria-label={strings.rejectNamed(name)} disabled={busy} onClick={onReject} className={rejectButton}>
                {strings.rejectEllipsis}
            </button>
            <button type="button" aria-label={strings.approveNamed(name)} disabled={busy} onClick={onApprove} className={approveButton}>
                {strings.approve}
            </button>
        </li>
    );
}

/** The requests waiting for the person's approval, with the buttons to decide them; nothing when there are none. */
export function Approvals({ approvals, macos }: Readonly<{ approvals: ApprovalView[]; macos: boolean }>) {
    const [busy, setBusy] = useState(false);
    const [problem, setProblem] = useState<string | null>(null);
    const [rejectingUuid, setRejectingUuid] = useState<string | null>(null);
    // A request that left the list, decided elsewhere or no longer waiting, is not asked about any more.
    const rejecting = approvals.find((approval) => approval.uuid === rejectingUuid) ?? null;
    useEffect(() => {
        if (rejecting === null) {
            setRejectingUuid(null);
        }
    }, [rejecting]);

    const decide = (approval: ApprovalView, decision: ApprovalDecision, comment: string | null) => {
        setBusy(true);
        setProblem(null);
        decideApproval(approval.uuid, decision, comment).then(
            () => {
                setBusy(false);
                setRejectingUuid(null);
            },
            (error) => {
                setBusy(false);
                setProblem(approvalProblem(approvalFailure(error)));
            },
        );
    };

    if (approvals.length === 0 && problem === null) {
        return null;
    }
    const note = (
        <>
            {problem !== null && rejecting === null && (
                <p role="alert" className="text-caption text-bad">
                    {problem}
                </p>
            )}
            {rejecting && (
                <RejectDialog
                    approval={rejecting}
                    busy={busy}
                    problem={problem}
                    macos={macos}
                    onReject={(comment) => decide(rejecting, 'reject', comment)}
                    onCancel={() => setRejectingUuid(null)}
                />
            )}
        </>
    );
    return (
        <Group title={strings.waitingForYourApproval} note={note}>
            {approvals.map((approval) => (
                <ApprovalRow
                    key={approval.uuid}
                    approval={approval}
                    busy={busy}
                    onApprove={() => decide(approval, 'approve', null)}
                    onReject={() => {
                        setProblem(null);
                        setRejectingUuid(approval.uuid);
                    }}
                />
            ))}
        </Group>
    );
}
