import type { ComponentType } from 'react';
import { openSettings, type Platform } from './bridge';
import { CertificateIcon, type Icon, OverviewIcon, SettingsIcon } from './design-system/icons';
import { Certificates } from './sections/Certificates';
import { Overview } from './sections/Overview';
import { Settings } from './sections/Settings';
import { strings } from './strings';

export interface Section {
    id: string;
    label: string;
    icon: Icon;
    Component: ComponentType;
    /** Shown only when this holds for the listings the person may use; a section without a rule is always shown. */
    visibleWhen?: (listings: string[]) => boolean;
    /** Shown only on these platforms; a section without the list is shown on all. */
    platforms?: Platform[];
    /** Opens the section somewhere else instead of showing `Component` as a page. */
    open?: () => void;
}

export const sections: Section[] = [
    { id: 'overview', label: strings.overview, icon: OverviewIcon, Component: Overview },
    { id: 'certificates', label: strings.certificates, icon: CertificateIcon, Component: Certificates, platforms: ['macos', 'windows'] },
];

export function visibleSections(listings: string[], platform: Platform, candidates: Section[] = sections): Section[] {
    return candidates.filter((section) => (section.platforms?.includes(platform) ?? true) && (section.visibleWhen?.(listings) ?? true));
}

const settings = (label: string): Section => ({ id: 'settings', label, icon: SettingsIcon, Component: Settings });
const settingsEntries = {
    windows: settings(strings.settings),
    linux: settings(strings.preferences),
    macos: { ...settings(strings.settingsWindow), open: () => void openSettings().catch(() => undefined) },
};

/** Settings is at the bottom of the sidebar: a page on Windows and Linux, a window of its own on macOS. */
export function settingsSection(platform: Platform): Section {
    return settingsEntries[platform];
}
