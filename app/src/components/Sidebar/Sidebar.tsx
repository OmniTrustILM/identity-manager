import { type KeyboardEvent, useRef, useState } from 'react';
import type { Section } from '../../sections';
import { strings } from '../../strings';

interface SidebarProps {
    sections: Section[];
    current: string;
    onSelect: (id: string) => void;
    /** Heads the list where the window has no title of its own. */
    title?: string;
}

export function Sidebar({ sections, current, onSelect, title }: Readonly<SidebarProps>) {
    const [focused, setFocused] = useState(current);
    const buttons = useRef<(HTMLButtonElement | null)[]>([]);

    const moveFocus = (event: KeyboardEvent, index: number) => {
        const last = sections.length - 1;
        const target = { ArrowDown: Math.min(index + 1, last), ArrowUp: Math.max(index - 1, 0), Home: 0, End: last }[event.key];
        if (target !== undefined) {
            event.preventDefault();
            buttons.current[target]?.focus();
        }
    };

    return (
        <nav
            aria-label={strings.navigation}
            className="flex w-sidebar shrink-0 flex-col gap-s1 bg-transparent p-s2 in-data-[os=linux]:bg-sidebar in-data-[os=macos]:pt-titlebar"
        >
            {title && <p className="px-s3 py-s2 text-title text-primary">{title}</p>}
            {sections.map(({ id, label, icon: SectionIcon }, index) => (
                <button
                    key={id}
                    ref={(button) => {
                        buttons.current[index] = button;
                    }}
                    type="button"
                    tabIndex={id === focused ? 0 : -1}
                    aria-current={id === current ? 'page' : undefined}
                    onFocus={() => setFocused(id)}
                    onKeyDown={(event) => moveFocus(event, index)}
                    onClick={() => onSelect(id)}
                    className="flex h-control items-center gap-s2 rounded-control px-s3 text-left text-body text-primary hover:bg-row-hover aria-[current=page]:bg-row-current motion-safe:transition-colors"
                >
                    <SectionIcon aria-hidden className="size-icon shrink-0" />
                    {label}
                </button>
            ))}
        </nav>
    );
}
