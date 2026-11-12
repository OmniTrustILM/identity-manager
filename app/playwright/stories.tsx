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

export function ShellStory({ platform }: { platform: Platform }) {
    return (
        <AppInfoContext.Provider value={{ name: 'Identity Manager', version: '0.1.0', platform }}>
            <Shell sections={sections} />
        </AppInfoContext.Provider>
    );
}

export function TraySummaryStory({ platform }: { platform: Platform }) {
    return (
        <AppInfoContext.Provider value={{ name: 'Identity Manager', version: '0.1.0', platform }}>
            <TraySummary />
        </AppInfoContext.Provider>
    );
}
