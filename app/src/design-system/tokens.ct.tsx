import { expect, test } from '@playwright/experimental-ct-react';

type Os = 'macos' | 'windows' | 'linux';
type Scheme = 'light' | 'dark';

const expected = {
    macos: {
        font: '-apple-system, BlinkMacSystemFont, system-ui, sans-serif',
        radius: '6px',
        control: '28px',
        light: { surface: '#FFFFFF', sidebar: '#ECECEC', text: '#000000D9' },
        dark: { surface: '#1E1E1E', sidebar: '#2A2A2A', text: '#FFFFFFD9' },
    },
    windows: {
        font: '"Segoe UI Variable Text", "Segoe UI Variable", "Segoe UI", system-ui, sans-serif',
        radius: '4px',
        control: '32px',
        light: { surface: '#FBFBFB', sidebar: '#F3F3F3', text: '#1A1A1A' },
        dark: { surface: '#272727', sidebar: '#202020', text: '#FFFFFF' },
    },
    linux: {
        font: 'Cantarell, "Adwaita Sans", system-ui, sans-serif',
        radius: '6px',
        control: '34px',
        light: { surface: '#FAFAFB', sidebar: '#EBEBED', text: '#323232' },
        dark: { surface: '#222226', sidebar: '#2E2E32', text: '#FFFFFF' },
    },
} as const;

const perSystemTokens = [
    'font-family',
    'font-size-body',
    'font-size-caption',
    'font-size-title',
    'font-size-large-title',
    'radius-control',
    'radius-window',
    'control-height',
    'focus-width',
    'focus-offset',
    ...[
        'surface',
        'sidebar',
        'sidebar-tint',
        'titlebar',
        'text-primary',
        'text-secondary',
        'text-tertiary',
        'separator',
        'accent',
        'accent-text',
        'row-hover',
        'row-current',
        'focus-ring',
        'status-fine',
        'status-attention',
        'status-wait',
        'status-bad',
    ].map((name) => `color-${name}`),
].map((name) => `--im-${name}`);

const systems = Object.keys(expected) as Os[];
const schemes: Scheme[] = ['light', 'dark'];

// A colour as [r, g, b, alpha to two places]: engines serialise alpha differently.
function channels(colour: string): number[] {
    const hex = colour.match(/^#([0-9a-f]{6})([0-9a-f]{2})?$/i);
    if (hex?.[1]) {
        const value = Number.parseInt(hex[1], 16);
        const alpha = hex[2] ? Number.parseInt(hex[2], 16) / 255 : 1;
        return [value >> 16, (value >> 8) & 255, value & 255, Math.round(alpha * 100) / 100];
    }
    const [r = 0, g = 0, b = 0, a = 1] = (colour.match(/[\d.]+/g) ?? []).map(Number);
    return [r, g, b, Math.round(a * 100) / 100];
}

// Chromium serialises BlinkMacSystemFont, an alias of system-ui, as system-ui.
const plain = (family: string) =>
    family
        .replace(/["']/g, '')
        .replace(/\s*,\s*/g, ',')
        .replace('BlinkMacSystemFont', 'system-ui');

const cases: { os: Os; media: Scheme; theme: Scheme | null; shown: Scheme }[] = systems.flatMap((os) => [
    { os, media: 'light', theme: null, shown: 'light' },
    { os, media: 'dark', theme: null, shown: 'dark' },
    { os, media: 'dark', theme: 'light', shown: 'light' },
    { os, media: 'light', theme: 'dark', shown: 'dark' },
]);

for (const { os, media, theme, shown } of cases) {
    test(`${os} shows ${shown} tokens for a ${media} system${theme ? ` with data-theme=${theme}` : ''}`, async ({ mount, page }) => {
        await page.emulateMedia({ colorScheme: media });
        await page.evaluate(
            ({ system, override }) => {
                document.documentElement.dataset.os = system;
                if (override) {
                    document.documentElement.dataset.theme = override;
                } else {
                    delete document.documentElement.dataset.theme;
                }
            },
            { system: os, override: theme },
        );
        await mount(
            <div data-testid="probe" className="h-control rounded-control bg-surface font-sans text-primary">
                <nav className="bg-sidebar">Sidebar</nav>
            </div>,
        );

        const style = await page.getByTestId('probe').evaluate((element) => {
            const computed = getComputedStyle(element);
            const sidebar = getComputedStyle(element.querySelector('nav') as Element);
            return {
                font: computed.fontFamily,
                radius: computed.borderTopLeftRadius,
                height: computed.height,
                surface: computed.backgroundColor,
                text: computed.color,
                sidebar: sidebar.backgroundColor,
            };
        });
        const want = expected[os];

        expect(plain(style.font)).toBe(plain(want.font));
        expect(style.radius).toBe(want.radius);
        expect(style.height).toBe(want.control);
        expect(channels(style.surface)).toEqual(channels(want[shown].surface));
        expect(channels(style.sidebar)).toEqual(channels(want[shown].sidebar));
        expect(channels(style.text)).toEqual(channels(want[shown].text));
    });
}

for (const os of systems) {
    for (const scheme of schemes) {
        test(`${os} defines every per-system token in ${scheme}`, async ({ page, mount }) => {
            await page.emulateMedia({ colorScheme: scheme });
            await page.evaluate((system) => {
                document.documentElement.dataset.os = system;
            }, os);
            await mount(<div />);

            const missing = await page.evaluate(
                (names) => names.filter((name) => getComputedStyle(document.documentElement).getPropertyValue(name).trim() === ''),
                perSystemTokens,
            );

            expect(missing).toEqual([]);
        });
    }
}
