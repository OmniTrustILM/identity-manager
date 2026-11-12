import { listen } from '@tauri-apps/api/event';
import { colorScheme, type Scheme } from './bridge';

function applyScheme(scheme: Scheme | null) {
    if (scheme) {
        document.documentElement.dataset.theme = scheme;
    } else {
        delete document.documentElement.dataset.theme;
    }
}

/**
 * Sets `data-theme` to the colour scheme the desktop asks for and keeps it current; returns the function that stops it.
 * Without a scheme the attribute is absent and `prefers-color-scheme` decides.
 */
export async function followSystemScheme(): Promise<() => void> {
    let changed = false;
    const unlisten = await listen<Scheme | null>('color-scheme', (event) => {
        changed = true;
        applyScheme(event.payload);
    });
    // An event is newer than the answer to a read that was still on its way when it arrived.
    const initial = await colorScheme();
    if (!changed) {
        applyScheme(initial);
    }
    return unlisten;
}
