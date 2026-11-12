import type { SelectHTMLAttributes } from 'react';
import { SelectIcon } from '../../design-system/icons';

type SelectProps<T extends string> = Omit<SelectHTMLAttributes<HTMLSelectElement>, 'value' | 'onChange'> & {
    value: T;
    options: readonly T[];
    onChange: (value: T) => void;
};

export function Select<T extends string>({ value, options, onChange, ...rest }: Readonly<SelectProps<T>>) {
    return (
        <span className="relative inline-flex items-center has-disabled:opacity-disabled">
            <select
                {...rest}
                value={value}
                onChange={(event) => onChange(event.target.value as T)}
                className="h-control w-select appearance-none rounded-control border border-field-edge bg-field pr-s5 pl-s3 text-body text-primary"
            >
                {options.map((option) => (
                    <option key={option} value={option}>
                        {option}
                    </option>
                ))}
            </select>
            <SelectIcon aria-hidden className="pointer-events-none absolute right-s2 size-icon text-secondary" />
        </span>
    );
}
