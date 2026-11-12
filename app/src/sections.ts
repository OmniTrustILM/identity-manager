import type { ComponentType } from 'react';
import { type Icon, OverviewIcon } from './design-system/icons';
import { Overview } from './sections/Overview';
import { strings } from './strings';

export interface Section {
    id: string;
    label: string;
    icon: Icon;
    Component: ComponentType;
}

export const sections: Section[] = [{ id: 'overview', label: strings.overview, icon: OverviewIcon, Component: Overview }];
