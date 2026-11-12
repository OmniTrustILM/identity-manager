import { useEffect, useState } from 'react';
import { AppInfoContext } from './app-info';
import { type AppInfo, getAppInfo, reportReady, windowLabel } from './bridge';
import { Shell } from './components/Shell/Shell';
import { TraySummary } from './components/TraySummary/TraySummary';
import { sections } from './sections';
import { strings } from './strings';
import { followSystemScheme } from './theme';

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
        // The summary reports itself, together with the height of its content.
        if (info && windowLabel() !== 'summary') {
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
                    {windowLabel() === 'summary' ? <TraySummary /> : <Shell sections={sections} />}
                </AppInfoContext.Provider>
            )}
        </>
    );
}
