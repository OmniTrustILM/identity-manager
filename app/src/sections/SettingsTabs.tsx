import { type KeyboardEvent, type ReactNode, useEffect, useId, useRef, useState } from 'react';
import { setWindowTitle } from '../bridge';
import type { Icon } from '../design-system/icons';
import { strings } from '../strings';

export interface Pane {
    id: string;
    title: string;
    icon: Icon;
    content: ReactNode;
}

const rememberedKey = 'settings-pane';

function remembered(): string | null {
    try {
        return localStorage.getItem(rememberedKey);
    } catch {
        return null;
    }
}

function remember(id: string) {
    try {
        localStorage.setItem(rememberedKey, id);
    } catch {
        // Without storage the window opens on its first pane next time.
    }
}

/** The macOS Settings window: a toolbar of panes under the title, one pane shown at a time, as in other Mac apps. */
export function SettingsTabs({ panes }: Readonly<{ panes: [Pane, ...Pane[]] }>) {
    const [chosen, setChosen] = useState(remembered);
    const buttons = useRef<(HTMLButtonElement | null)[]>([]);
    const id = useId();
    const current = panes.find((pane) => pane.id === chosen) ?? panes[0];
    // A pane that went away, such as Connection after signing out, is forgotten, so it does not come back by itself.
    if (chosen !== null && chosen !== current.id) {
        setChosen(current.id);
    }

    const title = current.title;
    useEffect(() => {
        setWindowTitle(title).catch(() => undefined);
    }, [title]);

    const choose = (pane: Pane) => {
        setChosen(pane.id);
        remember(pane.id);
    };

    const move = (event: KeyboardEvent, index: number) => {
        const last = panes.length - 1;
        const target = { ArrowRight: Math.min(index + 1, last), ArrowLeft: Math.max(index - 1, 0), Home: 0, End: last }[event.key];
        const pane = target === undefined ? undefined : panes[target];
        if (pane) {
            event.preventDefault();
            choose(pane);
            buttons.current[target ?? 0]?.focus();
        }
    };

    return (
        <div className="flex flex-col">
            {/* The toolbar sits in the title bar, so it moves the window like one; its buttons stay buttons. */}
            <div
                role="tablist"
                aria-label={strings.settings}
                data-tauri-drag-region="deep"
                className="flex justify-center gap-s1 border-b border-separator bg-titlebar px-s4 pt-titlebar pb-s2"
            >
                {panes.map((pane, index) => (
                    <button
                        key={pane.id}
                        ref={(button) => {
                            buttons.current[index] = button;
                        }}
                        type="button"
                        role="tab"
                        id={`${id}-${pane.id}`}
                        aria-selected={pane === current}
                        aria-controls={`${id}-pane`}
                        tabIndex={pane === current ? 0 : -1}
                        onClick={() => choose(pane)}
                        onKeyDown={(event) => move(event, index)}
                        className="flex flex-col items-center gap-s1 rounded-control px-s3 py-s1 text-caption text-secondary hover:bg-row-hover aria-selected:bg-row-current aria-selected:text-accent motion-safe:transition-colors"
                    >
                        <pane.icon aria-hidden className="size-toolbar-icon" />
                        {pane.title}
                    </button>
                ))}
            </div>
            <div id={`${id}-pane`} role="tabpanel" aria-labelledby={`${id}-${current.id}`} className="p-s4">
                {current.content}
            </div>
        </div>
    );
}
