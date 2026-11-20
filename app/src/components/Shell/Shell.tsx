import { type ReactNode, useEffect, useState } from 'react';
import { useAppInfo } from '../../app-info';
import { onOpenSection, pendingSection } from '../../bridge';
import type { Section } from '../../sections';
import { Sidebar } from '../Sidebar/Sidebar';

interface ShellProps {
    sections: Section[];
    /** The entry apart from the sections, at the bottom of the sidebar; the shell can be asked to open it. */
    bottom?: Section;
    /** Shown across the top of the content, above the section. */
    banner?: ReactNode;
}

export function Shell({ sections, bottom, banner }: Readonly<ShellProps>) {
    const info = useAppInfo();
    const [current, setCurrent] = useState(sections[0]?.id);
    const entries = [...sections, ...(bottom ? [bottom] : [])];
    const open = entries.find((section) => section.id === current);
    const select = (id: string) => {
        const entry = entries.find((section) => section.id === id);
        if (entry?.open) {
            entry.open();
        } else {
            setCurrent(id);
        }
    };

    useEffect(() => {
        if (!bottom || bottom.open) {
            return;
        }
        // The tray menu asks for the page this way; it is the only section it opens. The request is kept until taken,
        // so a click made before this listener exists still opens it.
        const take = () =>
            pendingSection()
                .then((id) => id === bottom.id && setCurrent(id))
                .catch(() => undefined);
        const listening = onOpenSection(take)
            .then((stop) => {
                void take();
                return stop;
            })
            .catch(() => () => undefined);
        return () => {
            void listening.then((stop) => stop());
        };
    }, [bottom]);

    return (
        <div className="flex h-screen">
            <Sidebar
                sections={sections}
                bottom={bottom}
                current={current ?? ''}
                onSelect={select}
                title={info.platform === 'linux' ? info.name : undefined}
            />
            <div className="flex min-w-0 flex-1 flex-col bg-surface">
                {banner && <div className="in-data-[os=macos]:mt-titlebar">{banner}</div>}
                <main className={`flex-1 overflow-auto p-s5 ${banner ? '' : 'in-data-[os=macos]:pt-titlebar'}`}>
                    {open && <open.Component />}
                </main>
            </div>
        </div>
    );
}
