import { useEffect, useRef, useState } from 'react';
import { AppInfoContext, useAppInfo } from './app-info';
import { type AppInfo, getAppInfo, type Platform, reportReady, windowLabel } from './bridge';
import { Shell } from './components/Shell/Shell';
import { IlmWaitingContext } from './ilm-waiting';
import { TraySummary } from './components/TraySummary/TraySummary';
import { settingsSection, visibleSections } from './sections';
import { Settings } from './sections/Settings';
import { SignIn, UnreachableBanner } from './sections/SignIn';
import { Unlock } from './sections/Unlock';
import { useSession } from './session';
import { useInventory } from './useInventory';
import { strings } from './strings';
import { followSystemScheme } from './theme';

/** The shell of a signed-in person; the inventory is read only now, so that the sections can depend on it. */
function SignedIn({ listings, platform }: Readonly<{ listings: string[]; platform: Platform }>) {
    const { inventory } = useInventory();
    return <Shell sections={visibleSections(listings, platform, inventory)} bottom={settingsSection(platform)} />;
}

function Main({ platform }: Readonly<{ platform: Platform }>) {
    const { view, failed } = useSession();

    if (failed) {
        return <p role="alert">{strings.sessionLoadError}</p>;
    }
    switch (view?.state) {
        case 'signedIn':
            return <SignedIn listings={view.allowedListings} platform={platform} />;
        case 'signedOut':
        case 'signingIn':
            return <SignIn view={view} />;
        case 'unreachable':
            return (
                <IlmWaitingContext.Provider value>
                    <Shell
                        sections={visibleSections([], platform)}
                        bottom={settingsSection(platform)}
                        banner={<UnreachableBanner view={view} />}
                    />
                </IlmWaitingContext.Provider>
            );
        case 'locked':
            return <Unlock automatic />;
        default:
            return null;
    }
}

/** The macOS Settings window takes the height of its content, so that every group shows without scrolling. */
function SettingsWindow() {
    const info = useAppInfo();
    const content = useRef<HTMLDivElement>(null);

    useEffect(() => {
        // The window fits its content, so the page has nothing to scroll and should not bounce like it does.
        document.documentElement.style.overscrollBehavior = 'none';
    }, []);

    useEffect(() => {
        const element = content.current;
        if (!element) {
            return;
        }
        const observer = new ResizeObserver(() => {
            const height = Math.ceil(element.getBoundingClientRect().height);
            if (height > 0) {
                reportReady({ ...info, height }).catch(() => undefined);
            }
        });
        observer.observe(element);
        return () => observer.disconnect();
    }, [info]);

    return (
        <div className="min-h-screen bg-sidebar">
            <div ref={content}>
                <Settings />
            </div>
            {/* The title bar is drawn over the content, so its strip moves the window whatever Settings shows. */}
            <div data-tauri-drag-region className="fixed inset-x-0 top-0 h-titlebar" />
        </div>
    );
}

function Content({ label, platform }: Readonly<{ label: string; platform: Platform }>) {
    switch (label) {
        case 'summary':
            return <TraySummary />;
        case 'settings':
            return <SettingsWindow />;
        default:
            return (
                <>
                    <Main platform={platform} />
                    {/* The macOS window has no title bar of its own over the content, so its top strip moves it. */}
                    {platform === 'macos' && <div data-tauri-drag-region className="fixed inset-x-0 top-0 h-titlebar" />}
                </>
            );
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
        // The summary and the Settings window report themselves, together with the height of their content.
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
