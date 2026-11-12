import { useState } from 'react';
import { useAppInfo } from '../../app-info';
import type { Section } from '../../sections';
import { Sidebar } from '../Sidebar/Sidebar';

export function Shell({ sections }: Readonly<{ sections: Section[] }>) {
    const info = useAppInfo();
    const [current, setCurrent] = useState(sections[0]?.id);
    const open = sections.find((section) => section.id === current);

    return (
        <div className="flex h-screen">
            <Sidebar
                sections={sections}
                current={current ?? ''}
                onSelect={setCurrent}
                title={info.platform === 'linux' ? info.name : undefined}
            />
            <main className="flex-1 overflow-auto bg-surface p-s5">{open && <open.Component />}</main>
        </div>
    );
}
