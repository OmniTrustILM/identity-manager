import { useEffect, useLayoutEffect, useRef } from 'react';
import { useAppInfo } from '../../app-info';
import { hideSummary, openMainWindow, reportReady } from '../../bridge';
import { AppIcon } from '../../design-system/icons';
import { strings } from '../../strings';

export function TraySummary() {
    const info = useAppInfo();
    const open = useRef<HTMLButtonElement>(null);
    const content = useRef<HTMLDivElement>(null);

    useLayoutEffect(() => {
        const height = Math.ceil(content.current?.getBoundingClientRect().height ?? 0);
        reportReady(height > 0 ? { ...info, height } : info).catch(() => undefined);
    }, [info]);

    useEffect(() => {
        const focusOpen = () => open.current?.focus();
        const hideOnEscape = (event: KeyboardEvent) => {
            if (event.key === 'Escape') {
                hideSummary().catch(() => undefined);
            }
        };
        focusOpen();
        window.addEventListener('focus', focusOpen);
        document.addEventListener('keydown', hideOnEscape);
        return () => {
            window.removeEventListener('focus', focusOpen);
            document.removeEventListener('keydown', hideOnEscape);
        };
    }, []);

    return (
        // The macOS window is transparent with a material of its own; elsewhere the summary paints its surface.
        <div className="min-h-screen w-tray bg-surface text-body text-primary in-data-[os=macos]:bg-transparent">
            <div ref={content} className="flex flex-col gap-s4 p-s4">
                <header className="flex items-center gap-s3">
                    <AppIcon aria-hidden className="size-icon shrink-0 text-accent" />
                    <div>
                        <h1 className="text-title">{info.name}</h1>
                        <p className="text-caption text-secondary">{strings.version(info.version)}</p>
                    </div>
                </header>
                <button
                    ref={open}
                    type="button"
                    onClick={() => openMainWindow().catch(() => undefined)}
                    className="h-control rounded-control bg-accent px-s3 text-body text-on-accent"
                >
                    {strings.openApp}
                </button>
            </div>
        </div>
    );
}
