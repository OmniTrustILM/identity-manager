import { useEffect, useState } from 'react';
import { getSession, onSessionChanged, type SessionView } from './bridge';

/** The session as the core reports it: read once, then kept current by its events. `failed` is set when it cannot be read. */
export function useSession(): { view: SessionView | null; failed: boolean } {
    const [view, setView] = useState<SessionView | null>(null);
    const [failed, setFailed] = useState(false);

    useEffect(() => {
        let current = true;
        // An event that arrives before the first read is newer than that read.
        let changed = false;
        const listening = onSessionChanged((next) => {
            changed = true;
            if (current) {
                setView(next);
            }
        }).catch(() => () => undefined);
        getSession().then(
            (loaded) => current && !changed && setView(loaded),
            () => current && setFailed(true),
        );
        return () => {
            current = false;
            void listening.then((stop) => stop());
        };
    }, []);

    return { view, failed };
}
