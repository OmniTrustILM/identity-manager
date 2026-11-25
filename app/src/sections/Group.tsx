import { type ReactNode, useId } from 'react';

const panel = 'rounded-window border border-separator bg-card';
const heading = 'text-caption font-semibold text-secondary';

/** The classes of one row of a group. */
export const row = 'flex items-center gap-s3 px-s3 py-s2';

/** A titled list of rows; `note` is shown under the list. */
export function Group({ title, children, note }: Readonly<{ title: string; children: ReactNode; note?: ReactNode }>) {
    const id = useId();
    return (
        <section aria-labelledby={id} className="flex flex-col gap-s2">
            <h2 id={id} className={heading}>
                {title}
            </h2>
            <ul className={`flex flex-col divide-y divide-separator ${panel}`}>{children}</ul>
            {note}
        </section>
    );
}
