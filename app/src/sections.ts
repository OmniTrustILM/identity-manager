import type { ComponentType } from 'react';
import { openSettings, type Platform } from './bridge';
import { type Icon, OverviewIcon, SettingsIcon } from './design-system/icons';
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
    /** Opens the section somewhere else instead of showing `Component` as a page. */
    open?: () => void;
}

export const sections: Section[] = [{ id: 'overview', label: strings.overview, icon: OverviewIcon, Component: Overview }];

export function visibleSections(listings: string[], candidates: Section[] = sections): Section[] {
    return candidates.filter((section) => section.visibleWhen?.(listings) ?? true);
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
