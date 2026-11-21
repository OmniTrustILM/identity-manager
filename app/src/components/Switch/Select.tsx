import type { SelectHTMLAttributes } from 'react';
import { SelectIcon } from '../../design-system/icons';

type SelectProps<T extends string> = Omit<SelectHTMLAttributes<HTMLSelectElement>, 'value' | 'onChange'> & {
    value: T;
    options: readonly T[];
    /** The text shown for an option; the option itself when absent. */
    label?: (option: T) => string;
    onChange: (value: T) => void;
    /** Takes the width of its container instead of the width of a setting. */
    fill?: boolean;
};

export function Select<T extends string>({ value, options, label = String, onChange, fill = false, ...rest }: Readonly<SelectProps<T>>) {
    return (
        <span className={`relative items-center has-disabled:opacity-disabled ${fill ? 'flex' : 'inline-flex'}`}>
            <select
                {...rest}
                value={value}
                onChange={(event) => onChange(event.target.value as T)}
                className={`h-control appearance-none rounded-control border border-field-edge bg-field pr-s5 pl-s3 text-body text-primary ${fill ? 'w-full' : 'w-select'}`}
            >
                {options.map((option) => (
                    <option key={option} value={option}>
                        {label(option)}
                    </option>
                ))}
            </select>
            <SelectIcon aria-hidden className="pointer-events-none absolute right-s2 size-icon text-secondary" />
        </span>
    );
}
