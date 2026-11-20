import { type KeyboardEvent, useEffect, useRef, useState } from 'react';
import { type IlmCertificateView, type IlmPageView, ilmCertificates, type InventoryView } from '../bridge';
import { ArchivedIcon, LaptopIcon, MonitorIcon, SearchIcon } from '../design-system/icons';
import { strings } from '../strings';
import { arrowTarget, codeLabel, Field, FingerprintGroup, Group, status, validationTone } from './certificateParts';

const pageSize = 50;
const searchPause = 400;

type Result = { page: IlmPageView | null; error: string | null; loading: boolean };

const columns = 'grid grid-cols-[minmax(0,2fr)_minmax(0,1fr)_minmax(0,1.2fr)] items-start gap-x-s3 px-s3';
const pagerButton = 'h-control rounded-control border border-button-edge bg-button px-s3 text-body text-primary disabled:opacity-disabled';

type System = 'macos' | 'windows';

function Detail({ certificate, now }: Readonly<{ certificate: IlmCertificateView; now: number }>) {
    const state = status(certificate, now);
    return (
        <section aria-labelledby="ilm-certificate-title" className="flex min-w-0 flex-col gap-s4">
            <header className="flex flex-col gap-s1">
                <h2 id="ilm-certificate-title" className="text-title font-semibold text-primary">
                    {certificate.name}
                </h2>
                {state.text !== '' && <p className={`text-caption ${state.expired ? 'text-bad' : 'text-secondary'}`}>{state.text}</p>}
            </header>
            <Group title={strings.certificateGroupTitle}>
                {certificate.notBefore !== null && <Field label={strings.validFrom}>{strings.date(certificate.notBefore)}</Field>}
                {certificate.notAfter !== null && <Field label={strings.validUntil}>{strings.date(certificate.notAfter)}</Field>}
                {certificate.issuerName !== null && <Field label={strings.issuer}>{certificate.issuerName}</Field>}
                {certificate.serial !== null && <Field label={strings.serial}>{certificate.serial}</Field>}
            </Group>
            <Group title={strings.inIlmGroupTitle}>
                <Field label={strings.stateRow}>{codeLabel(certificate.state)}</Field>
                <Field label={strings.validationRow} tone={validationTone(certificate.validationStatus)}>
                    {codeLabel(certificate.validationStatus)}
                </Field>
                <Field label={strings.raProfileRow}>{certificate.raProfile?.name ?? strings.notManaged}</Field>
                {certificate.owner !== null && <Field label={strings.ownerRow}>{certificate.owner}</Field>}
                {certificate.groups.length > 0 && <Field label={strings.groupsRow}>{certificate.groups.join(', ')}</Field>}
            </Group>
            {certificate.fingerprint !== null && <FingerprintGroup fingerprint={certificate.fingerprint} />}
        </section>
    );
}

function List({
    items,
    selected,
    now,
    local,
    system,
    onSelect,
}: Readonly<{
    items: IlmCertificateView[];
    selected: number;
    now: number;
    local: ReadonlySet<string>;
    system: System;
    onSelect: (index: number) => void;
}>) {
    const rows = useRef<(HTMLDivElement | null)[]>([]);
    const Computer = system === 'macos' ? LaptopIcon : MonitorIcon;

    const move = (event: KeyboardEvent, index: number) => {
        const target = arrowTarget(event.key, index, items.length - 1);
        if (target !== undefined) {
            event.preventDefault();
            onSelect(target);
            rows.current[target]?.focus();
        }
    };

    return (
        <div className="flex min-w-0 flex-col gap-s1">
            <div aria-hidden className={`${columns} border-b border-separator pb-s2 text-caption font-semibold text-secondary`}>
                <span>{strings.certificateHeader}</span>
                <span>{strings.ilmStateHeader}</span>
                <span>{strings.statusHeader}</span>
            </div>
            <div role="listbox" aria-label={strings.ilmCertificatesListLabel} className="flex flex-col">
                {items.map((certificate, index) => {
                    const state = status(certificate, now);
                    const here = certificate.fingerprint !== null && local.has(certificate.fingerprint);
                    const label = [
                        certificate.name,
                        certificate.issuerName,
                        codeLabel(certificate.state),
                        state.text,
                        here ? strings.onThisComputer(system) : null,
                        certificate.archived ? strings.archived : null,
                    ]
                        .filter(Boolean)
                        .join(', ');
                    return (
                        <div
                            key={certificate.uuid}
                            ref={(row) => {
                                rows.current[index] = row;
                            }}
                            role="option"
                            tabIndex={index === selected ? 0 : -1}
                            aria-selected={index === selected}
                            aria-label={label}
                            onClick={() => onSelect(index)}
                            onKeyDown={(event) => move(event, index)}
                            className={`${columns} cursor-default rounded-control py-s2 hover:bg-row-hover aria-selected:bg-row-current motion-safe:transition-colors`}
                        >
                            <span className="flex min-w-0 flex-col">
                                <span className="flex items-center gap-s1 text-body text-primary">
                                    {certificate.name}
                                    {here && (
                                        <span role="img" aria-label={strings.onThisComputer(system)} title={strings.onThisComputer(system)}>
                                            <Computer aria-hidden className="size-icon shrink-0 text-secondary" />
                                        </span>
                                    )}
                                </span>
                                <span className="text-caption text-secondary">{certificate.issuerName}</span>
                            </span>
                            <span className="flex flex-col text-body text-secondary">
                                {codeLabel(certificate.state)}
                                {certificate.archived && (
                                    <span className="flex items-center gap-s1 text-caption text-tertiary">
                                        <ArchivedIcon aria-hidden className="size-icon shrink-0" />
                                        {strings.archived}
                                    </span>
                                )}
                            </span>
                            <span className={`text-body ${state.expired ? 'text-bad' : 'text-secondary'}`}>{state.text}</span>
                        </div>
                    );
                })}
            </div>
        </div>
    );
}

function Pager({
    shown,
    count,
    offline,
    onPage,
}: Readonly<{ shown: IlmPageView; count: number; offline: boolean; onPage: (page: number) => void }>) {
    const from = count > 0 ? (shown.pageNumber - 1) * pageSize + 1 : 0;
    return (
        <nav className="flex items-center justify-between border-t border-separator pt-s3">
            <button
                tabIndex={0}
                type="button"
                disabled={offline || shown.pageNumber <= 1}
                onClick={() => onPage(shown.pageNumber - 1)}
                className={pagerButton}
            >
                {strings.previous}
            </button>
            {count > 0 && (
                <output className="text-body text-secondary">{strings.pageRange(from, from + count - 1, shown.totalItems)}</output>
            )}
            <button
                tabIndex={0}
                type="button"
                disabled={offline || shown.pageNumber >= shown.totalPages}
                onClick={() => onPage(shown.pageNumber + 1)}
                className={pagerButton}
            >
                {strings.next}
            </button>
        </nav>
    );
}

/** Everything ILM lists that the person may see, a page at a time, with a search by name; it offers no actions. */
export function IlmCertificates({
    inventory,
    local,
    system,
    onTotal,
}: Readonly<{ inventory: InventoryView; local: ReadonlySet<string>; system: System; onTotal: (total: number | null) => void }>) {
    const offline = inventory.status.state === 'offline';
    const since = inventory.status.state === 'offline' ? inventory.status.since : null;
    const cached = inventory.firstPage;
    const checkedAt = inventory.checkedAt;
    const [text, setText] = useState('');
    const [query, setQuery] = useState('');
    const [page, setPage] = useState(1);
    const [retry, setRetry] = useState(0);
    const [chosen, setChosen] = useState<string | null>(null);
    const [result, setResult] = useState<Result>({ page: null, error: null, loading: true });
    const latest = useRef(0);
    const pause = useRef<ReturnType<typeof setTimeout> | null>(null);

    // Each request carries a number; an answer to an older one is dropped. A new check of ILM asks again.
    // biome-ignore lint/correctness/useExhaustiveDependencies: `retry` and `checkedAt` only repeat the request.
    useEffect(() => {
        if (offline) {
            return;
        }
        const id = ++latest.current;
        setResult((current) => ({ ...current, error: null, loading: true }));
        ilmCertificates(page, query === '' ? null : query).then(
            (answer) => id === latest.current && setResult({ page: answer, error: null, loading: false }),
            (error) =>
                id === latest.current &&
                setResult((current) => ({ ...current, error: String(error) || strings.ilmLoadFailed, loading: false })),
        );
        return () => {
            latest.current += 1;
        };
    }, [offline, page, query, retry, checkedAt]);

    useEffect(() => {
        if (offline) {
            setResult({ page: cached, error: null, loading: false });
        }
    }, [offline, cached]);

    useEffect(
        () => () => {
            if (pause.current !== null) {
                clearTimeout(pause.current);
            }
        },
        [],
    );

    const total = result.page?.totalItems ?? null;
    useEffect(() => {
        onTotal(total);
        return () => onTotal(null);
    }, [total, onTotal]);

    const commit = (value: string) => {
        if (pause.current !== null) {
            clearTimeout(pause.current);
            pause.current = null;
        }
        const next = value.trim();
        if (next !== query) {
            setQuery(next);
            setPage(1);
        }
    };

    const items = result.page?.certificates ?? [];
    const found = items.findIndex((certificate) => certificate.uuid === chosen);
    const selected = Math.max(found, 0);
    const now = Date.now();
    const shown = result.page;

    return (
        <div className="flex flex-col gap-s4">
            <div className="relative max-w-form">
                <SearchIcon
                    aria-hidden
                    className="pointer-events-none absolute top-1/2 left-s3 size-icon -translate-y-1/2 text-secondary"
                />
                <input
                    type="search"
                    value={text}
                    disabled={offline}
                    placeholder={strings.searchByName}
                    aria-label={strings.searchByName}
                    spellCheck={false}
                    autoCapitalize="off"
                    autoCorrect="off"
                    onChange={(event) => {
                        const value = event.target.value;
                        setText(value);
                        if (pause.current !== null) {
                            clearTimeout(pause.current);
                        }
                        pause.current = setTimeout(() => commit(value), searchPause);
                    }}
                    onKeyDown={(event) => event.key === 'Enter' && commit(text)}
                    className="h-control w-full rounded-control border border-input-edge bg-input pr-s3 pl-[calc(var(--spacing-s3)+var(--spacing-icon)+var(--spacing-s2))] text-body text-primary disabled:opacity-disabled"
                />
            </div>
            {offline && <p className="text-body text-secondary">{strings.ilmOffline(since)}</p>}
            {result.error !== null && (
                <div role="alert" className="flex flex-col items-start gap-s3 text-body text-bad">
                    <p>{result.error}</p>
                    <button tabIndex={0} type="button" onClick={() => setRetry((count) => count + 1)} className={pagerButton}>
                        {strings.tryAgain}
                    </button>
                </div>
            )}
            {result.error === null && !result.loading && shown !== null && items.length === 0 && (
                <p className="text-body text-secondary">{strings.noIlmCertificates}</p>
            )}
            {items.length === 0 && shown !== null && shown.pageNumber > 1 && (
                <Pager shown={shown} count={0} offline={offline} onPage={setPage} />
            )}
            {items.length > 0 && (
                <div className="flex flex-col gap-s5 @3xl:flex-row">
                    <div className="flex min-w-0 flex-[3] flex-col gap-s3">
                        <List
                            items={items}
                            selected={selected}
                            now={now}
                            local={local}
                            system={system}
                            onSelect={(index) => setChosen(items[index]?.uuid ?? null)}
                        />
                        {shown && <Pager shown={shown} count={items.length} offline={offline} onPage={setPage} />}
                    </div>
                    <div className="min-w-0 flex-[2] border-t border-separator pt-s4 @3xl:border-t-0 @3xl:border-l @3xl:pt-0 @3xl:pl-s5">
                        {items[selected] && <Detail certificate={items[selected]} now={now} />}
                    </div>
                </div>
            )}
        </div>
    );
}
