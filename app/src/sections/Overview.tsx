import { useEffect, useId, useState } from 'react';
import { useAppInfo } from '../app-info';
import {
    type AttentionItemView,
    type InventoryView,
    type LocalCertificateView,
    localCertificates,
    onInventoryChanged,
    type SummaryView,
} from '../bridge';
import { attentionDetail, attentionLook } from '../attention';
import { ExpiredIcon, ExpiringIcon, FineIcon, type Icon, NotInIlmIcon, SignInKeyIcon } from '../design-system/icons';
import { useIlmWaiting } from '../ilm-waiting';
import { useNavigation } from '../navigation';
import { strings } from '../strings';
import { useInventory } from '../useInventory';
import { useSummary } from '../useSummary';
import { AddToIlm } from './AddToIlm';
import { SyncLine } from './certificateParts';

type System = 'macos' | 'windows';

const secondary = 'h-control shrink-0 rounded-control border border-button-edge bg-button px-s3 text-body text-primary';
const panel = 'rounded-window border border-separator bg-card';
const heading = 'text-caption font-semibold text-secondary';
const chartHeight = 56;

function Tile({ count, label, Icon, tone }: Readonly<{ count: number; label: string; Icon: Icon; tone: string }>) {
    const muted = count === 0;
    return (
        <li className={`flex flex-col gap-s1 p-s3 ${panel}`}>
            <span className={`text-large-title font-semibold ${muted ? 'text-tertiary' : 'text-primary'}`}>{count}</span>
            <span className={`flex items-center gap-s1 text-body ${muted ? 'text-tertiary' : 'text-secondary'}`}>
                <Icon aria-hidden className={`size-icon shrink-0 ${muted ? '' : tone}`} />
                {label}
            </span>
        </li>
    );
}

function Tiles({ summary }: Readonly<{ summary: SummaryView }>) {
    const { valid, expiring, expired, notInIlm } = summary.counts;
    return (
        <ul aria-label={strings.countsLabel} className="grid grid-flow-col auto-cols-fr gap-s3">
            <Tile count={valid} label={strings.valid} Icon={FineIcon} tone="text-fine" />
            <Tile count={expiring} label={strings.expiringSoon} Icon={ExpiringIcon} tone="text-attention" />
            <Tile count={expired} label={strings.expired} Icon={ExpiredIcon} tone="text-bad" />
            {notInIlm !== null && <Tile count={notInIlm} label={strings.notInIlm} Icon={NotInIlmIcon} tone="text-secondary" />}
        </ul>
    );
}

interface Unmatched {
    certificates: LocalCertificateView[];
    /** Whether ILM can be asked now, so that they can be added. */
    canAdd: boolean;
    onAdd: () => void;
}

function Row({ item, unmatched, system }: Readonly<{ item: AttentionItemView; unmatched: Unmatched; system: System }>) {
    const { showCertificate } = useNavigation();
    const { Icon, tone, textTone } = attentionLook(item);
    const names = unmatched.certificates.map((certificate) => certificate.name);
    let title: string;
    let detail: string | null = null;
    let action: { label: string; name: string; run: () => void } | null = null;
    if (item.kind === 'notInIlm') {
        title = strings.notInIlmCount(item.count, system);
        detail = names.length > 0 ? strings.nameList(names) : null;
        action = unmatched.canAdd && names.length > 0 ? { label: strings.addToIlm, name: strings.addToIlm, run: unmatched.onAdd } : null;
    } else {
        title = item.name;
        detail = attentionDetail(item);
        action = { label: strings.show, name: strings.showCertificate(item.name), run: () => showCertificate(item.fingerprint) };
    }
    return (
        <li className="flex items-center gap-s3 px-s3 py-s2">
            <Icon aria-hidden className={`size-icon shrink-0 ${tone}`} />
            <div className="flex min-w-0 flex-1 flex-col">
                <span className="text-body text-primary">{title}</span>
                {detail !== null && <span className={`text-caption ${textTone}`}>{detail}</span>}
            </div>
            {action && (
                <button tabIndex={0} type="button" aria-label={action.name} onClick={action.run} className={secondary}>
                    {action.label}
                </button>
            )}
        </li>
    );
}

function Attention({ summary, unmatched, system }: Readonly<{ summary: SummaryView; unmatched: Unmatched; system: System }>) {
    const id = useId();
    return (
        <section aria-labelledby={id} className="flex flex-col gap-s2">
            <h2 id={id} className={heading}>
                {strings.needsAttention}
            </h2>
            {summary.attention.length === 0 ? (
                <p className={`flex items-center gap-s2 px-s3 py-s3 text-body text-primary ${panel}`}>
                    <FineIcon aria-hidden className="size-icon shrink-0 text-fine" />
                    {strings.nothingNeedsAttention}
                </p>
            ) : (
                <ul className={`flex flex-col divide-y divide-separator ${panel}`}>
                    {summary.attention.map((item) => (
                        <Row
                            key={item.kind === 'notInIlm' ? item.kind : `${item.kind}:${item.fingerprint}`}
                            item={item}
                            unmatched={unmatched}
                            system={system}
                        />
                    ))}
                </ul>
            )}
        </section>
    );
}

function Chart({ summary }: Readonly<{ summary: SummaryView }>) {
    const id = useId();
    const from = new Date(summary.computedAt);
    // The months run from the current one, in the local time zone.
    const months = summary.months.map((count, index) => ({
        count,
        at: new Date(from.getFullYear(), from.getMonth() + index, 1).getTime(),
    }));
    const most = Math.max(...summary.months);
    const expiring = summary.attention.filter((item) => item.kind === 'expiring');
    return (
        <section aria-labelledby={id} className="flex flex-col gap-s2">
            <h2 id={id} className={heading}>
                {strings.expiryChart}
            </h2>
            <div className={`flex flex-col gap-s3 p-s4 ${panel}`}>
                <ol aria-label={strings.expiryChartLabel} className="grid grid-cols-12 items-end gap-s2">
                    {months.map(({ count, at }, index) => (
                        <li key={at} className="flex flex-col items-center gap-s1 text-caption">
                            <span className={count > 0 ? 'font-semibold text-primary' : 'text-tertiary'}>{count}</span>
                            <span className="flex items-end" style={{ height: chartHeight }}>
                                <span
                                    aria-hidden
                                    className={`w-s4 rounded-t-control ${count > 0 ? 'bg-accent' : 'bg-separator'}`}
                                    style={{ height: count > 0 ? Math.max((count / most) * chartHeight, 4) : 2 }}
                                />
                            </span>
                            <span className={index === 0 ? 'font-semibold text-primary' : 'text-secondary'}>{strings.month(at)}</span>
                        </li>
                    ))}
                </ol>
                {expiring.length > 0 && (
                    <ul
                        aria-label={strings.expiringList}
                        className="flex flex-col gap-s1 border-t border-separator pt-s3 text-body text-secondary"
                    >
                        {expiring.map((item) => (
                            <li key={item.fingerprint}>
                                <span className="text-primary">{item.name}</span> {strings.expiresOn(strings.date(item.on), item.days)}
                            </li>
                        ))}
                    </ul>
                )}
            </div>
        </section>
    );
}

const lookedUp = (inventory: InventoryView | null, fingerprint: string) =>
    inventory?.listed === true && inventory.checked.includes(fingerprint) && !inventory.matches[fingerprint];

/** How the certificates on this computer stand: counts, what needs attention and the expiry of the next 12 months. */
export function Overview() {
    const { platform } = useAppInfo();
    const system: System = platform === 'macos' ? 'macos' : 'windows';
    const { inventory, syncError, sync } = useInventory();
    const summary = useSummary();
    const [local, setLocal] = useState<LocalCertificateView[]>([]);
    const [adding, setAdding] = useState<LocalCertificateView[] | null>(null);

    useEffect(() => {
        // The names of the certificates ILM does not know are read again whenever the inventory changes.
        let current = true;
        const read = () =>
            localCertificates().then(
                (items) => current && setLocal(items),
                () => undefined,
            );
        const listening = onInventoryChanged(read).catch(() => undefined);
        void listening.then(read);
        return () => {
            current = false;
            void listening.then((stop) => stop?.());
        };
    }, []);

    const unmatched = local.filter((certificate) => lookedUp(inventory, certificate.fingerprint));
    const waiting = useIlmWaiting();
    const canAdd = inventory !== null && inventory.status.state !== 'offline' && !waiting;
    const empty =
        summary !== null && summary.attention.length === 0 && summary.counts.valid + summary.counts.expiring + summary.counts.expired === 0;

    return (
        <div className="flex flex-col gap-s4">
            <header className="flex flex-col gap-s1">
                <h1 className="text-large-title font-semibold text-primary">{strings.overview}</h1>
                {inventory && <SyncLine inventory={inventory} onSync={sync} />}
                {syncError !== null && (
                    <p role="alert" className="text-caption text-bad">
                        {syncError}
                    </p>
                )}
            </header>
            {summary && <Tiles summary={summary} />}
            {summary && empty && (
                <p className={`flex items-center gap-s2 px-s3 py-s3 text-body text-secondary ${panel}`}>
                    <SignInKeyIcon aria-hidden className="size-icon shrink-0" />
                    {strings.noCertificatesWithKey(system)}
                </p>
            )}
            {summary && !empty && (
                <>
                    <Attention
                        summary={summary}
                        unmatched={{ certificates: unmatched, canAdd, onAdd: () => setAdding(unmatched) }}
                        system={system}
                    />
                    <Chart summary={summary} />
                </>
            )}
            {adding && <AddToIlm certificates={adding} system={system} onClose={() => setAdding(null)} />}
        </div>
    );
}
