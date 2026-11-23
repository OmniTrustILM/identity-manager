import type { Page } from '@playwright/test';

/**
 * WebKit hands the page the keyboard a moment after it mounts; keys pressed earlier are lost.
 * On Linux it sometimes never does, so the page takes it.
 */
export async function keyboardReady(page: Page) {
    await page.evaluate(() => window.focus());
    await page.waitForFunction(() => document.hasFocus());
}

/**
 * The file chooser that `open` brings up. Playwright starts intercepting the chooser only once the browser has
 * taken the listener, so a key pressed in the same breath can open the real, unseen dialog instead (Chromium on Linux).
 */
export async function fileChooserOpenedBy(page: Page, open: () => Promise<void>) {
    const chooser = page.waitForEvent('filechooser');
    await page.evaluate(() => undefined);
    await open();
    return chooser;
}
