import { expect, test } from '@playwright/experimental-ct-react';
import type { Locator, Page } from '@playwright/test';
import { keyboardReady } from '../../../playwright/focus';
import { ControlsStory } from '../../../playwright/stories';
import type { Platform } from '../../bridge';

type Scheme = 'light' | 'dark';

const accents: Record<Platform, Record<Scheme, string>> = {
    macos: { light: 'rgb(0, 122, 255)', dark: 'rgb(10, 132, 255)' },
    windows: { light: 'rgb(0, 95, 184)', dark: 'rgb(96, 205, 255)' },
    linux: { light: 'rgb(53, 132, 228)', dark: 'rgb(53, 132, 228)' },
};
const offTracks: Record<Platform, Record<Scheme, string>> = {
    macos: { light: 'rgb(229, 229, 229)', dark: 'rgb(57, 57, 57)' },
    windows: { light: 'rgba(0, 0, 0, 0)', dark: 'rgba(0, 0, 0, 0)' },
    linux: { light: 'rgb(220, 220, 220)', dark: 'rgb(61, 61, 64)' },
};
const sizes: Record<Platform, { width: number; height: number }> = {
    macos: { width: 38, height: 22 },
    windows: { width: 40, height: 20 },
    linux: { width: 46, height: 26 },
};
const travels: Record<Platform, number> = { macos: 16, windows: 20, linux: 20 };
const captions: Record<Platform, string> = { macos: '11px', windows: '12px', linux: '12px' };

async function open(page: Page, mount: (component: React.ReactElement) => Promise<Locator>, os: Platform, scheme: Scheme, locked = false) {
    await page.emulateMedia({ colorScheme: scheme, reducedMotion: 'reduce' });
    await page.evaluate((system) => {
        document.documentElement.dataset.os = system;
    }, os);
    return mount(<ControlsStory platform={os} locked={locked} />);
}

test('the switch and the select have their roles and names', async ({ mount, page }) => {
    await open(page, mount, 'macos', 'light');

    await expect(page.getByRole('switch', { name: 'Start at login' })).toBeChecked();
    await expect(page.getByRole('combobox', { name: 'Log level' })).toHaveValue('info');
    await expect(page.getByRole('switch', { name: 'Disabled switch' })).toBeDisabled();
});

test('the keyboard alone operates the switch and the select', async ({ mount, page }) => {
    await open(page, mount, 'linux', 'light');
    await keyboardReady(page);
    const toggle = page.getByRole('switch', { name: 'Start at login' });
    const level = page.getByRole('combobox', { name: 'Log level' });

    await page.keyboard.press('Tab');
    await expect(toggle).toBeFocused();
    await page.keyboard.press('Space');
    await expect(toggle).not.toBeChecked();
    await page.keyboard.press('Space');
    await expect(toggle).toBeChecked();

    await page.keyboard.press('Tab');
    await expect(level).toBeFocused();
    await level.selectOption('debug');
    await expect(level).toHaveValue('debug');
});

test('a disabled switch is skipped by Tab', async ({ mount, page }) => {
    await open(page, mount, 'windows', 'light');
    await keyboardReady(page);

    await page.keyboard.press('Tab');
    await page.keyboard.press('Tab');

    await expect(page.getByRole('combobox', { name: 'Log level' })).toBeFocused();
});

test('a keyboard-focused switch and select show a focus ring', async ({ mount, page }) => {
    await open(page, mount, 'windows', 'dark');
    await keyboardReady(page);

    for (const name of ['switch', 'combobox'] as const) {
        await page.keyboard.press('Tab');
        const ring = await page
            .getByRole(name)
            .first()
            .evaluate((element) => {
                const style = getComputedStyle(element);
                return { style: style.outlineStyle, width: style.outlineWidth };
            });
        expect(ring.style).not.toBe('none');
        expect(ring.width).not.toBe('0px');
    }
});

for (const os of ['macos', 'windows', 'linux'] as const) {
    for (const scheme of ['light', 'dark'] as const) {
        test(`on ${os} in ${scheme} the switch has its size and its on and off colours`, async ({ mount, page }) => {
            await open(page, mount, os, scheme);
            const toggle = page.getByRole('switch', { name: 'Start at login' });

            const on = await toggle.evaluate((element) => {
                const style = getComputedStyle(element);
                const box = element.getBoundingClientRect();
                return { background: style.backgroundColor, width: box.width, height: box.height };
            });
            await toggle.click();
            const off = await toggle.evaluate((element) => getComputedStyle(element).backgroundColor);

            expect(on.background).toBe(accents[os][scheme]);
            expect({ width: on.width, height: on.height }).toEqual(sizes[os]);
            expect(off).toBe(offTracks[os][scheme]);
        });

        test(`on ${os} in ${scheme} the thumb sits at the start when the switch is off and moves by the travel when it is on`, async ({
            mount,
            page,
        }) => {
            await open(page, mount, os, scheme);
            const toggle = page.getByRole('switch', { name: 'Start at login' });
            const shift = () => toggle.evaluate((element) => Number.parseFloat(getComputedStyle(element, '::before').translate));

            expect(await shift()).toBe(travels[os]);
            await toggle.click();
            expect(await shift()).toBe(0);
        });

        test(`on ${os} in ${scheme} the lock note shows the lock and the reason and the select is disabled`, async ({ mount, page }) => {
            await open(page, mount, os, scheme, true);
            const note = page.locator('#note');

            await expect(note).toBeVisible();
            await expect(note).toHaveText('Managed by your organization');
            await expect(note.locator('svg')).toBeVisible();
            expect(await note.evaluate((element) => getComputedStyle(element).fontSize)).toBe(captions[os]);
            const level = page.getByRole('combobox', { name: 'Log level' });
            await expect(level).toBeDisabled();
            await expect(level).toHaveAccessibleDescription('Managed by your organization');
        });
    }
}

for (const [os, visible] of [
    ['windows', true],
    ['macos', false],
    ['linux', false],
] as const) {
    test(`on ${os} the state word beside the switch is ${visible ? 'shown' : 'hidden'}`, async ({ mount, page }) => {
        await open(page, mount, os, 'light');
        const word = page.getByText('On', { exact: true }).first();

        if (visible) {
            await expect(word).toBeVisible();
        } else {
            await expect(word).toBeHidden();
        }
    });
}

test('the switch animates unless motion is reduced', async ({ mount, page }) => {
    await open(page, mount, 'macos', 'light');
    const toggle = page.getByRole('switch', { name: 'Start at login' });
    expect(await toggle.evaluate((element) => getComputedStyle(element).transitionDuration)).toBe('0s');

    await page.emulateMedia({ reducedMotion: 'no-preference' });

    expect(await toggle.evaluate((element) => getComputedStyle(element).transitionDuration)).not.toBe('0s');
});
