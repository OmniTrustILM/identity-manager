import type { Page } from '@playwright/test';

/** WebKit hands the page the keyboard a moment after it mounts; keys pressed earlier are lost. */
export async function keyboardReady(page: Page) {
    await page.waitForFunction(() => document.hasFocus());
}
