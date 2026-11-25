import { useState } from 'react';
import { useAppInfo } from '../app-info';
import type { InventoryView, MyRequestView, PreparedView } from '../bridge';
import { strings } from '../strings';
import { useInventory } from '../useInventory';
import { Approvals } from './Approvals';
import { Group, row } from './Group';
import { Request } from './Request';

const day = 24 * 60 * 60 * 1000;
const issueButton = 'h-control shrink-0 rounded-control bg-accent px-s3 text-body text-on-accent';

/** Whether the section has something to show: a request waiting for the person's approval, a certificate prepared in advance or a request of the person. */
export const hasRequests = (inventory: InventoryView | null) =>
    inventory !== null && (inventory.approvals.length > 0 || inventory.prepared.length > 0 || inventory.requests.length > 0);

type Standing = { kind: 'ready'; days: number | null } | { kind: 'ended' } | { kind: 'locked' };

/** Whether a prepared certificate can still be issued by the person, and how long it can. */
export function standing(prepared: PreparedView, now: number): Standing {
    const registration = prepared.registration;
    if (registration?.state === 'locked') {
        return { kind: 'locked' };
    }
    if (registration?.state === 'expired') {
        return { kind: 'ended' };
    }
    const expiresAt = registration?.expiresAt ?? null;
    if (expiresAt === null) {
        return { kind: 'ready', days: null };
    }
    if (expiresAt <= now) {
        return { kind: 'ended' };
    }
    return { kind: 'ready', days: Math.max(Math.ceil((expiresAt - now) / day), 1) };
}

function PreparedRow({ prepared, now, onIssue }: Readonly<{ prepared: PreparedView; now: number; onIssue: () => void }>) {
    const state = standing(prepared, now);
    let middle: string | null = null;
    if (state.kind === 'ended') {
        middle = strings.issueWindowEnded;
    } else if (state.kind === 'locked') {
        middle = strings.lockedAfterAttempts;
    } else if (state.days !== null) {
        middle = strings.issueWithin(state.days);
    }
    return (
        <li className={row}>
            <div className="flex min-w-0 flex-1 flex-col">
                <span className="text-body text-primary">{prepared.name}</span>
                <span className="text-caption text-secondary">{prepared.raProfile.name}</span>
            </div>
            <span className="min-w-0 flex-1 text-body text-secondary">{middle}</span>
            {state.kind === 'ready' ? (
                <button type="button" aria-label={strings.issueNamed(prepared.name)} onClick={onIssue} className={issueButton}>
                    {strings.issue}
                </button>
            ) : (
                <span className="shrink-0 text-caption text-secondary">{strings.askAdministrator}</span>
            )}
        </li>
    );
}

function RequestRow({ request }: Readonly<{ request: MyRequestView }>) {
    return (
        <li className={row}>
            <div className="flex min-w-0 flex-1 flex-col">
                <span className="text-body text-primary">{request.label}</span>
                <span className="text-caption text-secondary">{strings.requestedAt(request.since)}</span>
            </div>
            <span className="flex min-w-0 flex-1 items-center gap-s2 text-body text-primary">
                <span aria-hidden className="size-s2 shrink-0 rounded-full bg-accent" />
                {request.state === 'pendingApproval' ? strings.waitingForApproval : strings.beingIssued}
            </span>
        </li>
    );
}

/** The certificates prepared for the person to issue, and the requests of the person that ILM has not finished. */
export function Requests() {
    const { platform } = useAppInfo();
    const { inventory } = useInventory();
    const [issuing, setIssuing] = useState<PreparedView | null>(null);
    const approvals = inventory?.approvals ?? [];
    const prepared = inventory?.prepared ?? [];
    const requests = inventory?.requests ?? [];
    const now = Date.now();
    const ready = prepared.filter((candidate) => standing(candidate, now).kind === 'ready').length;
    const summary = strings.requestsSummary(approvals.length, ready, requests.length);

    return (
        <div className="flex flex-col gap-s4">
            <header className="flex flex-col gap-s1">
                <h1 className="text-large-title font-semibold text-primary">{strings.requests}</h1>
                {summary !== '' && <p className="text-body text-secondary">{summary}</p>}
            </header>
            <Approvals approvals={approvals} macos={platform === 'macos'} />
            {prepared.length > 0 && (
                <Group title={strings.readyToIssue}>
                    {prepared.map((candidate) => (
                        <PreparedRow key={candidate.uuid} prepared={candidate} now={now} onIssue={() => setIssuing(candidate)} />
                    ))}
                </Group>
            )}
            {requests.length > 0 && (
                <Group title={strings.myRequests}>
                    {requests.map((request) => (
                        <RequestRow key={request.uuid ?? `${request.label}-${request.since}`} request={request} />
                    ))}
                </Group>
            )}
            {inventory && !hasRequests(inventory) && (
                <div className="flex flex-col items-center gap-s1 py-s5 text-center">
                    <h2 className="text-title font-semibold text-primary">{strings.nothingToIssue}</h2>
                    <p className="text-body text-secondary">{strings.nothingToIssueHint}</p>
                </div>
            )}
            {issuing && <Request prepared={issuing} platform={platform} onClose={() => setIssuing(null)} />}
        </div>
    );
}
