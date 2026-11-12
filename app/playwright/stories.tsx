import { useMemo } from 'react';
import { AppInfoContext } from '../src/app-info';
import type { Platform } from '../src/bridge';
import { Shell } from '../src/components/Shell/Shell';
import { TraySummary } from '../src/components/TraySummary/TraySummary';
import { OverviewIcon } from '../src/design-system/icons';
import type { Section } from '../src/sections';

const First = () => <p>First content</p>;
const Second = () => <p>Second content</p>;

const sections: Section[] = [
    { id: 'first', label: 'First', icon: OverviewIcon, Component: First },
    { id: 'second', label: 'Second', icon: OverviewIcon, Component: Second },
];

type StoryProps = Readonly<{ platform: Platform }>;

const useInfo = (platform: Platform) => useMemo(() => ({ name: 'Identity Manager', version: '0.1.0', platform }), [platform]);

export function ShellStory({ platform }: StoryProps) {
    return (
        <AppInfoContext.Provider value={useInfo(platform)}>
            <Shell sections={sections} />
        </AppInfoContext.Provider>
    );
}

export function TraySummaryStory({ platform }: StoryProps) {
    return (
        <AppInfoContext.Provider value={useInfo(platform)}>
            <TraySummary />
        </AppInfoContext.Provider>
    );
}
