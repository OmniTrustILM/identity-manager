import { useEffect, useState } from 'react';
import { AppInfoContext } from './app-info';
import { type AppInfo, getAppInfo, type Platform, reportReady, windowLabel } from './bridge';
import { Shell } from './components/Shell/Shell';
import { TraySummary } from './components/TraySummary/TraySummary';
import { settingsSection, visibleSections } from './sections';
import { Settings } from './sections/Settings';
import { SignIn } from './sections/SignIn';
import { useSession } from './session';
import { strings } from './strings';
import { followSystemScheme } from './theme';

function Main({ platform }: Readonly<{ platform: Platform }>) {
    const { view, failed } = useSession();

    if (failed) {
        return <p role="alert">{strings.sessionLoadError}</p>;
    }
    switch (view?.state) {
        case 'signedIn':
            return <Shell sections={visibleSections(view.allowedListings)} bottom={settingsSection(platform)} />;
        case 'signedOut':
        case 'signingIn':
            return <SignIn view={view} />;
        default:
            return null;
    }
}

function Content({ label, platform }: Readonly<{ label: string; platform: Platform }>) {
    switch (label) {
        case 'summary':
            return <TraySummary />;
        case 'settings':
            return <Settings />;
        default:
            return <Main platform={platform} />;
    }
}

export function App() {
    const [info, setInfo] = useState<AppInfo | null>(null);
    const [failed, setFailed] = useState(false);

    useEffect(() => {
        let current = true;
        getAppInfo().then(
            (loaded) => {
                if (current) {
                    document.documentElement.dataset.os = loaded.platform;
                    setInfo(loaded);
                }
            },
            () => current && setFailed(true),
        );
        return () => {
            current = false;
        };
    }, []);

    useEffect(() => {
        // The summary reports itself, together with the height of its content; Settings is not part of the check.
        if (info && windowLabel() === 'main') {
            reportReady(info).catch(() => undefined);
        }
    }, [info]);

    const platform = info?.platform;
    useEffect(() => {
        // The Linux web view does not follow the desktop's colour scheme, so the shell passes it on.
        if (platform !== 'linux') {
            return;
        }
        const following = followSystemScheme().catch(() => () => undefined);
        return () => {
            void following.then((stop) => stop());
        };
    }, [platform]);

    return (
        <>
            {failed && <p role="alert">{strings.loadError}</p>}
            {info && (
                <AppInfoContext.Provider value={info}>
                    <Content label={windowLabel()} platform={info.platform} />
                </AppInfoContext.Provider>
            )}
        </>
    );
}
