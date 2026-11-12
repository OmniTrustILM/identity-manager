import { useEffect, useState } from 'react';
import { useAppInfo } from '../../app-info';
import { onOpenSection, pendingSection } from '../../bridge';
import type { Section } from '../../sections';
import { Sidebar } from '../Sidebar/Sidebar';

interface ShellProps {
    sections: Section[];
    /** The entry apart from the sections, at the bottom of the sidebar; the shell can be asked to open it. */
    bottom?: Section;
}

export function Shell({ sections, bottom }: Readonly<ShellProps>) {
    const info = useAppInfo();
    const [current, setCurrent] = useState(sections[0]?.id);
    const open = [...sections, ...(bottom ? [bottom] : [])].find((section) => section.id === current);

    useEffect(() => {
        if (!bottom) {
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
                onSelect={setCurrent}
                title={info.platform === 'linux' ? info.name : undefined}
            />
            <main className="flex-1 overflow-auto bg-surface p-s5">{open && <open.Component />}</main>
        </div>
    );
}
