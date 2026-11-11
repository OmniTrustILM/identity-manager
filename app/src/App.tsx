import { useEffect, useState } from 'react';
import { type AppInfo, getAppInfo, reportReady } from './bridge';
import { strings } from './strings';

export function App() {
    const [info, setInfo] = useState<AppInfo | null>(null);
    const [failed, setFailed] = useState(false);

    useEffect(() => {
        let current = true;
        getAppInfo().then(
            (loaded) => current && setInfo(loaded),
            () => current && setFailed(true),
        );
        return () => {
            current = false;
        };
    }, []);

    useEffect(() => {
        if (info) {
            reportReady(info).catch(() => undefined);
        }
    }, [info]);

    return (
        <main>
            {failed && <p role="alert">{strings.loadError}</p>}
            {info && (
                <>
                    <h1>{info.name}</h1>
                    <p>{strings.version(info.version)}</p>
                </>
            )}
        </main>
    );
}
