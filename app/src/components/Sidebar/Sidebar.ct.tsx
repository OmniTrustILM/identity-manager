import { expect, test } from '@playwright/experimental-ct-react';
import { keyboardReady } from '../../../playwright/focus';
import { ShellStory } from '../../../playwright/stories';
import type { Platform } from '../../bridge';

async function setup(page: import('@playwright/test').Page, os: Platform, reducedMotion: 'reduce' | 'no-preference' = 'no-preference') {
    await page.emulateMedia({ colorScheme: 'light', reducedMotion });
    await page.evaluate((system) => {
        document.documentElement.dataset.os = system;
    }, os);
}

const shell = (platform: Platform) => <ShellStory platform={platform} />;

test('Tab reaches the sidebar, arrows move between entries and Enter opens one', async ({ mount, page }) => {
    await setup(page, 'macos');
    await mount(shell('macos'));
    await keyboardReady(page);

    await page.keyboard.press('Tab');
    await expect(page.getByRole('button', { name: 'First' })).toBeFocused();
    await page.keyboard.press('ArrowDown');
    await expect(page.getByRole('button', { name: 'Second' })).toBeFocused();
    await page.keyboard.press('Enter');

    await expect(page.getByRole('button', { name: 'Second' })).toHaveAttribute('aria-current', 'page');
    await expect(page.getByText('Second content')).toBeVisible();
    await page.keyboard.press('ArrowUp');
    await expect(page.getByRole('button', { name: 'First' })).toBeFocused();
});

test('a keyboard-focused entry shows a focus ring', async ({ mount, page }) => {
    await setup(page, 'windows');
    await mount(shell('windows'));
    await keyboardReady(page);

    await page.keyboard.press('Tab');
    await expect(page.getByRole('button', { name: 'First' })).toBeFocused();
    const ring = await page.getByRole('button', { name: 'First' }).evaluate((element) => {
        const style = getComputedStyle(element);
        return { style: style.outlineStyle, width: style.outlineWidth };
    });

    expect(ring.style).not.toBe('none');
    expect(ring.width).not.toBe('0px');
});

const backgrounds: [Platform, string][] = [
    ['macos', 'rgba(0, 0, 0, 0)'],
    ['windows', 'rgba(0, 0, 0, 0)'],
    ['linux', 'rgb(235, 235, 237)'],
];

for (const [os, colour] of backgrounds) {
    test(`on ${os} the sidebar background is ${colour}`, async ({ mount, page }) => {
        await setup(page, os);
        await mount(shell(os));

        const background = await page
            .getByRole('navigation', { name: 'Sections' })
            .evaluate((element) => getComputedStyle(element).backgroundColor);

        expect(background).toBe(colour);
    });
}

test('on macOS the entries clear the window buttons', async ({ mount, page }) => {
    await setup(page, 'macos');
    await mount(shell('macos'));

    const top = await page.getByRole('navigation', { name: 'Sections' }).evaluate((element) => getComputedStyle(element).paddingTop);

    expect(top).toBe('28px');
});

test('hover and current states transition normally', async ({ mount, page }) => {
    await setup(page, 'linux');
    await mount(shell('linux'));

    const duration = await page.getByRole('button', { name: 'First' }).evaluate((element) => getComputedStyle(element).transitionDuration);

    expect(duration).not.toBe('0s');
});

test('with reduced motion no transition runs', async ({ mount, page }) => {
    await setup(page, 'linux', 'reduce');
    await mount(shell('linux'));

    const duration = await page.getByRole('button', { name: 'First' }).evaluate((element) => getComputedStyle(element).transitionDuration);

    expect(duration).toBe('0s');
});
