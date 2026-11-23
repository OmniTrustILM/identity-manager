import { type KeyboardEvent, useState } from 'react';
import type { AttributeFieldView, AttributeValue } from '../../bridge';
import { PlusIcon } from '../../design-system/icons';
import { strings } from '../../strings';
import { Select } from '../Switch/Select';
import { Switch } from '../Switch/Switch';
import { TextField } from '../TextField/TextField';
import { FieldFrame, type FieldProps, ReadOnlyField, useFieldIds } from './Field';
import { fromLocalInput, readable, textOf, toLocalInput } from './values';

const none = '';

export function SwitchField({ field, value, problem, disabled, onChange, onTouch }: Readonly<FieldProps>) {
    const ids = useFieldIds(field, problem);
    const on = value?.kind === 'bool' && value.value;
    return (
        <FieldFrame field={field} ids={ids} problem={problem}>
            <div className="flex items-center justify-between gap-s3">
                <span aria-hidden className="text-body text-secondary in-data-[os=windows]:hidden">
                    {on ? strings.switchOn : strings.switchOff}
                </span>
                <Switch
                    {...ids.control}
                    checked={on}
                    disabled={disabled || field.readOnly}
                    onChange={(checked) => {
                        onChange({ kind: 'bool', value: checked });
                        onTouch();
                    }}
                />
            </div>
        </FieldFrame>
    );
}

const addedText = (item: AttributeValue) => (item.kind === 'added' ? textOf(item.value) : '');

type Added = NonNullable<AttributeFieldView['valueKind']>;

const addedInput: Record<Added, { type: string; inputMode?: 'numeric' | 'decimal' }> = {
    text: { type: 'text' },
    integer: { type: 'text', inputMode: 'numeric' },
    float: { type: 'text', inputMode: 'decimal' },
    date: { type: 'date' },
    time: { type: 'time' },
    dateTime: { type: 'datetime-local' },
};

/** The field under an extensible list where the person types a value to add, in the kind of input the list holds. */
function AddValue({
    field,
    kind,
    disabled,
    onAdd,
}: Readonly<{ field: AttributeFieldView; kind: Added; disabled: boolean; onAdd: (value: AttributeValue) => void }>) {
    const [typed, setTyped] = useState('');
    const { type, inputMode } = addedInput[kind];
    const entry = kind === 'dateTime' ? fromLocalInput(typed) : typed.trim();
    const add = () => {
        if (entry) {
            onAdd({ kind: 'added', value: { kind, value: entry } as AttributeValue });
        }
        setTyped('');
    };
    const onKey = (event: KeyboardEvent) => {
        if (event.key === 'Enter') {
            event.preventDefault();
            add();
        }
    };
    return (
        <span className="relative flex items-center">
            <TextField
                aria-label={strings.addValueTo(field.label)}
                type={type}
                inputMode={inputMode}
                placeholder={strings.addValue}
                disabled={disabled}
                value={kind === 'dateTime' ? toLocalInput(typed) : typed}
                onChange={(event) => setTyped(event.target.value)}
                onKeyDown={onKey}
                className="pr-s5"
            />
            <button
                type="button"
                tabIndex={0}
                aria-label={strings.add}
                disabled={disabled || !entry}
                onClick={add}
                className="absolute right-s2 text-secondary disabled:opacity-disabled"
            >
                <PlusIcon aria-hidden className="size-icon" />
            </button>
        </span>
    );
}

const addedKey = 'added';

/** One value out of a list, with "None" first when the attribute is optional; an extensible list also takes one the person adds. */
export function SelectField({ field, value, options, problem, disabled, onChange, onTouch }: Readonly<FieldProps>) {
    const ids = useFieldIds(field, problem);
    if (field.readOnly) {
        return <ReadOnlyField field={field} text={readable(field, value, options)} />;
    }
    const added = value?.kind === 'added' ? addedText(value) : null;
    const fallback = added === null ? none : addedKey;
    const chosen = value?.kind === 'option' ? value.value : fallback;
    const labels = Object.fromEntries(options.map((option) => [option.key, option.label]));
    if (added !== null) {
        labels[addedKey] = added;
    }
    const keepsNone = !field.required || chosen === none;
    const noneLabel = field.required ? strings.selectValue : strings.none;
    return (
        <FieldFrame field={field} ids={ids} problem={problem}>
            <Select
                {...ids.control}
                fill
                disabled={disabled}
                value={chosen}
                options={keepsNone ? [none, ...Object.keys(labels)] : Object.keys(labels)}
                label={(option) => (option === none ? noneLabel : (labels[option] ?? option))}
                onChange={(next) => {
                    if (next !== addedKey) {
                        onChange(next === none ? undefined : { kind: 'option', value: next });
                    }
                    onTouch();
                }}
                onBlur={onTouch}
            />
            {field.extensible && field.valueKind && (
                <AddValue
                    field={field}
                    kind={field.valueKind}
                    disabled={disabled}
                    onAdd={(next) => {
                        onChange(next);
                        onTouch();
                    }}
                />
            )}
        </FieldFrame>
    );
}

/** Several values out of a list, as checkboxes; an extensible list also takes values the person adds. */
export function MultiSelectField({ field, value, options, problem, disabled, onChange, onTouch }: Readonly<FieldProps>) {
    const ids = useFieldIds(field, problem);
    if (field.readOnly) {
        return <ReadOnlyField field={field} text={readable(field, value, options)} />;
    }
    const items = value?.kind === 'options' ? value.value : [];
    const added = items.filter((item) => item.kind === 'added');
    const set = (next: AttributeValue[]) => {
        onChange(next.length ? { kind: 'options', value: next } : undefined);
        onTouch();
    };
    const toggle = (key: string, on: boolean) =>
        set(on ? [...items, { kind: 'option', value: key }] : items.filter((item) => item.kind !== 'option' || item.value !== key));
    const box = 'flex items-center gap-s2 text-body text-primary';
    const check = 'size-icon shrink-0 accent-accent';
    return (
        <FieldFrame field={field} ids={ids} problem={problem} group>
            <div
                aria-invalid={problem ? true : undefined}
                className="flex flex-col gap-s2 rounded-control border border-input-edge bg-input p-s2 aria-invalid:border-bad"
            >
                {options.map((option) => (
                    <label key={option.key} className={box}>
                        <input
                            type="checkbox"
                            tabIndex={0}
                            disabled={disabled}
                            checked={items.some((item) => item.kind === 'option' && item.value === option.key)}
                            aria-describedby={ids.control['aria-describedby']}
                            onChange={(event) => toggle(option.key, event.target.checked)}
                            className={check}
                        />
                        {option.label}
                    </label>
                ))}
                {added.map((item) => (
                    <label key={addedText(item)} className={box}>
                        <input
                            type="checkbox"
                            tabIndex={0}
                            disabled={disabled}
                            checked
                            aria-describedby={ids.control['aria-describedby']}
                            onChange={() => set(items.filter((other) => other !== item))}
                            className={check}
                        />
                        {addedText(item)}
                    </label>
                ))}
            </div>
            {field.extensible && field.valueKind && (
                <AddValue
                    field={field}
                    kind={field.valueKind}
                    disabled={disabled}
                    onAdd={(next) => {
                        if (!added.some((item) => addedText(item) === addedText(next))) {
                            set([...items, next]);
                        }
                    }}
                />
            )}
        </FieldFrame>
    );
}

/** A note from ILM: its label and its text, with nothing to fill in. */
export function InfoField({ field }: Readonly<FieldProps>) {
    return (
        <div className="flex flex-col gap-s1">
            <span className="text-caption font-semibold text-secondary">{field.label}</span>
            <p className="whitespace-pre-wrap text-body text-primary">{textOf(field.value ?? undefined)}</p>
        </div>
    );
}
