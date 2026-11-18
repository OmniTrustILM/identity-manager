import type { ComponentProps } from 'react';

const base =
    'h-control w-full rounded-control border border-input-edge bg-input px-s3 text-body text-primary read-only:bg-button disabled:opacity-disabled aria-invalid:border-bad';

/** The single-line field of the sign-in and of Settings; a read-only field takes the colour of a button. */
export function TextField({ className, ...rest }: Readonly<ComponentProps<'input'>>) {
    return (
        <input
            type="text"
            spellCheck={false}
            autoCapitalize="off"
            autoCorrect="off"
            {...rest}
            className={className ? `${base} ${className}` : base}
        />
    );
}
