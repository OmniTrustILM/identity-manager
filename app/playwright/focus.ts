import type { Page } from '@playwright/test';

/**
 * WebKit hands the page the keyboard a moment after it mounts; keys pressed earlier are lost.
 * On Linux it sometimes never does, so the page takes it.
 */
export async function keyboardReady(page: Page) {
    await page.evaluate(() => window.focus());
    await page.waitForFunction(() => document.hasFocus());
}
