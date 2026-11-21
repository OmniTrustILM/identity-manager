import { useCallback, useEffect, useRef, useState } from 'react';
import { onInventoryChanged, overview, type SummaryView } from './bridge';

/**
 * How the certificates on this computer stand, as the core summarises them; null while it is read, when nobody is
 * signed in, and while `enabled` is false (the application is locked, so nothing is asked).
 */
export function useSummary(enabled = true): SummaryView | null {
    const [summary, setSummary] = useState<SummaryView | null>(null);
    const latest = useRef(0);

    const read = useCallback(() => {
        const id = ++latest.current;
        overview().then(
            (view) => id === latest.current && setSummary(view ?? null),
            () => id === latest.current && setSummary(null),
        );
    }, []);

    useEffect(() => {
        if (!enabled) {
            setSummary(null);
            return;
        }
        let current = true;
        const listening = onInventoryChanged(read).catch(() => undefined);
        // Read only once listening, so that no change between the read and the listener is lost.
        void listening.then(() => current && read());
        return () => {
            current = false;
            latest.current += 1;
            void listening.then((stop) => stop?.());
        };
    }, [enabled, read]);

    return summary;
}
