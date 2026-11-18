import type { ComponentType } from 'react';
import type { Platform } from './bridge';
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
}

export const sections: Section[] = [{ id: 'overview', label: strings.overview, icon: OverviewIcon, Component: Overview }];

export function visibleSections(listings: string[], candidates: Section[] = sections): Section[] {
    return candidates.filter((section) => section.visibleWhen?.(listings) ?? true);
}

const settings = (label: string): Section => ({ id: 'settings', label, icon: SettingsIcon, Component: Settings });
const settingsPages = { windows: settings(strings.settings), linux: settings(strings.preferences) };

/** Settings is a page at the bottom of the sidebar on Windows and Linux; macOS opens it in a window of its own. */
export function settingsSection(platform: Platform): Section | undefined {
    return platform === 'macos' ? undefined : settingsPages[platform];
}
