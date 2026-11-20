import { useCallback, useEffect, useRef, useState } from 'react';
import { type InventoryView, ilmStatus, onInventoryChanged, syncNow } from './bridge';

/** What ILM is known to say about this computer; null until it is read, and while the application is locked. */
export function useInventory(): { inventory: InventoryView | null; sync: () => void; apply: (view: InventoryView) => void } {
    const [inventory, setInventory] = useState<InventoryView | null>(null);
    const latest = useRef(0);

    const read = useCallback(() => {
        const id = ++latest.current;
        ilmStatus().then(
            (view) => id === latest.current && setInventory(view ?? null),
            () => undefined,
        );
    }, []);

    useEffect(() => {
        let current = true;
        const listening = onInventoryChanged(read).catch(() => undefined);
        // Read only once listening, so that no change between the read and the listener is lost.
        void listening.then(() => current && read());
        return () => {
            current = false;
            latest.current += 1;
            void listening.then((stop) => stop?.());
        };
    }, [read]);

    const apply = useCallback((view: InventoryView) => {
        latest.current += 1;
        setInventory(view);
    }, []);

    const sync = useCallback(() => {
        syncNow().then(
            (view) => view && apply(view),
            () => undefined,
        );
    }, [apply]);

    return { inventory, sync, apply };
}
