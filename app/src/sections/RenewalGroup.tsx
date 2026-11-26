import { useId, useState } from 'react';
import { type InventoryView, type RenewalView, setRenewalSwitch } from '../bridge';
import { LockNote } from '../components/Switch/LockNote';
import { Switch } from '../components/Switch/Switch';
import { RenewStatus, useRenewNow } from '../renewNow';
import { strings } from '../strings';
import { Field, Group } from './certificateParts';

const linkButton = 'h-control self-start rounded-control text-body text-accent';
const primaryButton = 'h-button self-start rounded-control bg-accent px-s3 text-body text-on-accent disabled:opacity-disabled';

/** Whether the Renewal group is shown for a certificate: it can be renewed, or a renewal has replaced it. */
export const showsRenewal = (view: RenewalView | undefined): view is RenewalView => view !== undefined && (view.renewable || view.replaced);

/** The automatic renewal of a certificate on this computer, with Renew now; or the renewal that replaced it. */
export function RenewalGroup({
    fingerprint,
    view,
    apply,
    onShow,
}: Readonly<{
    fingerprint: string;
    view: RenewalView;
    apply: (view: InventoryView) => void;
    onShow: (fingerprint: string) => void;
}>) {
    const lockId = useId();
    const { progress, renew } = useRenewNow();
    const [switching, setSwitching] = useState(false);
    const [problem, setProblem] = useState<string | null>(null);

    if (view.replaced) {
        return (
            <div className="flex flex-col gap-s2">
                <Group title={strings.renewalGroupTitle}>
                    <Field label={strings.renewalGroupTitle}>
                        {view.replacedOn === null ? strings.replacedByRenewal : strings.replacedByRenewalOn(strings.date(view.replacedOn))}
                    </Field>
                </Group>
                {view.replacedBy !== null && (
                    <button tabIndex={0} type="button" onClick={() => onShow(view.replacedBy as string)} className={linkButton}>
                        {strings.showRenewedCertificate}
                    </button>
                )}
            </div>
        );
    }

    const toggle = (on: boolean) => {
        setSwitching(true);
        setProblem(null);
        setRenewalSwitch(fingerprint, on)
            .then(apply, (error) => setProblem(String(error) || strings.renewalSwitchFailed))
            .finally(() => setSwitching(false));
    };
    const working = view.waiting || progress?.kind === 'busy' || progress?.kind === 'working' || progress?.kind === 'done';

    return (
        <div className="flex flex-col gap-s2">
            <Group title={strings.renewalGroupTitle}>
                <dt className="text-secondary">{strings.renewAutomatically}</dt>
                <dd className="flex flex-col gap-s1">
                    <Switch
                        aria-label={strings.renewAutomatically}
                        aria-describedby={view.locked ? lockId : undefined}
                        checked={view.automatic}
                        disabled={view.locked || switching}
                        onChange={toggle}
                    />
                    {view.locked && <LockNote id={lockId} />}
                </dd>
                <Field label={strings.renewWhenRow}>
                    {view.from === null ? strings.daysBeforeExpiry(view.daysBefore) : strings.renewalFrom(strings.date(view.from))}
                </Field>
                <Field label={strings.renewKeyRow}>{view.newKey ? strings.renewNewKey : strings.renewSameKey}</Field>
            </Group>
            <p className="text-caption text-secondary">{strings.renewalHint}</p>
            {view.waiting && progress === null && (
                <output className="text-caption text-secondary">{strings.renewalWaitingForApproval}</output>
            )}
            <RenewStatus progress={progress} />
            {problem !== null && (
                <p role="alert" className="text-caption text-bad">
                    {problem}
                </p>
            )}
            <button tabIndex={0} type="button" disabled={working} onClick={() => renew(fingerprint)} className={primaryButton}>
                {strings.renewNow}
            </button>
        </div>
    );
}
