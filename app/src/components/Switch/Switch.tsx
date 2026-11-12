import type { InputHTMLAttributes } from 'react';
import { strings } from '../../strings';

type SwitchProps = Omit<InputHTMLAttributes<HTMLInputElement>, 'type' | 'role' | 'checked' | 'onChange'> & {
    checked: boolean;
    onChange: (checked: boolean) => void;
};

export function Switch({ checked, onChange, ...rest }: Readonly<SwitchProps>) {
    return (
        <span className="inline-flex items-center gap-s3">
            <span aria-hidden className="hidden text-body text-primary in-data-[os=windows]:inline">
                {checked ? strings.switchOn : strings.switchOff}
            </span>
            <input
                // WebKit leaves checkboxes out of the Tab order unless they say so.
                tabIndex={0}
                {...rest}
                type="checkbox"
                // biome-ignore lint/a11y/useAriaPropsForRole: the native checkbox exposes the checked state of the switch
                role="switch"
                checked={checked}
                onChange={(event) => onChange(event.target.checked)}
                className="relative h-switch-height w-switch-width shrink-0 appearance-none rounded-full border border-switch-edge bg-switch-off before:absolute before:top-1/2 before:left-switch-pad before:size-switch-thumb before:-translate-y-1/2 before:rounded-full before:bg-switch-thumb-off checked:border-accent checked:bg-accent checked:before:translate-x-switch-travel checked:before:bg-on-accent disabled:opacity-disabled motion-safe:transition-colors motion-safe:before:transition-transform"
            />
        </span>
    );
}
