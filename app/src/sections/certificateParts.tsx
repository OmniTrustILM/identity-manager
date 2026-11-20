import { type ReactNode, useId } from 'react';
import { strings } from '../strings';

const fingerprintLineBytes = 16;
const dayMs = 24 * 60 * 60 * 1000;

const startOfDay = (time: number) => new Date(time).setHours(0, 0, 0, 0);

/** When a certificate expires, in words; nothing is said when ILM does not give the dates. */
export function status(
    certificate: Readonly<{ notBefore: number | null; notAfter: number | null }>,
    now: number,
): { text: string; expired: boolean } {
    const { notBefore, notAfter } = certificate;
    if (notAfter === null) {
        return { text: '', expired: false };
    }
    if (notAfter <= now) {
        return { text: strings.expiredOn(strings.date(notAfter)), expired: true };
    }
    if (notBefore !== null && notBefore > now) {
        return { text: strings.validFromDate(strings.date(notBefore)), expired: false };
    }
    const days = Math.round((startOfDay(notAfter) - startOfDay(now)) / dayMs);
    if (days === 0) {
        return { text: strings.expiresToday, expired: false };
    }
    return { text: days === 1 ? strings.expiresTomorrow : strings.expiresInDays(days), expired: false };
}

/** ILM's codes, such as "pending_approval", as words. */
export function codeLabel(code: string): string {
    const words = code.replaceAll('_', ' ');
    return words.charAt(0).toUpperCase() + words.slice(1);
}

function fingerprintLines(fingerprint: string): string[] {
    const bytes = fingerprint.split(':');
    const lines: string[] = [];
    for (let at = 0; at < bytes.length; at += fingerprintLineBytes) {
        lines.push(bytes.slice(at, at + fingerprintLineBytes).join(':'));
    }
    return lines;
}

export function Group({ title, children }: Readonly<{ title: string; children: ReactNode }>) {
    const id = useId();
    return (
        <section aria-labelledby={id} className="flex flex-col gap-s2">
            <h3 id={id} className="text-caption font-semibold text-secondary">
                {title}
            </h3>
            <dl className="grid grid-cols-[minmax(0,1fr)_minmax(0,2fr)] gap-x-s3 gap-y-s2 text-body">{children}</dl>
        </section>
    );
}

export function Field({ label, children, tone = 'text-primary' }: Readonly<{ label: string; children: ReactNode; tone?: string }>) {
    return (
        <>
            <dt className="text-secondary">{label}</dt>
            <dd className={`break-all ${tone}`}>{children}</dd>
        </>
    );
}

export function FingerprintGroup({ fingerprint }: Readonly<{ fingerprint: string }>) {
    return (
        <section className="flex flex-col gap-s2">
            <h3 className="text-caption font-semibold text-secondary">{strings.fingerprintTitle}</h3>
            <p data-fingerprint className="select-text font-mono text-caption text-primary">
                {fingerprintLines(fingerprint).map((line) => (
                    <span key={line} className="block">
                        {line}
                    </span>
                ))}
            </p>
        </section>
    );
}

/** The status of the validation ILM did, coloured when it is good or bad. */
export function validationTone(code: string): string {
    if (code === 'valid') {
        return 'text-fine';
    }
    return ['failed', 'invalid', 'revoked', 'expired'].includes(code) ? 'text-bad' : 'text-primary';
}

/** An arrow-key list: moves the selection with Up, Down, Home and End and focuses the new row. */
export function arrowTarget(key: string, index: number, last: number): number | undefined {
    return { ArrowDown: Math.min(index + 1, last), ArrowUp: Math.max(index - 1, 0), Home: 0, End: last }[key];
}
