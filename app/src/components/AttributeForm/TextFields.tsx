import { useState } from 'react';
import { HideIcon, ShowIcon } from '../../design-system/icons';
import { strings } from '../../strings';
import { TextField } from '../TextField/TextField';
import { areaClass, FieldFrame, type FieldProps, ReadOnlyField, useFieldIds } from './Field';
import { fromLocalInput, readable, textOf, toLocalInput } from './values';

type LineKind = 'text' | 'integer' | 'float' | 'date' | 'time';

interface LineProps extends FieldProps {
    kind: LineKind;
    type?: string;
    inputMode?: 'numeric' | 'decimal';
    placeholder?: string;
}

function Line({ kind, type, inputMode, placeholder, ...props }: Readonly<LineProps>) {
    const { field, value, options, problem, disabled, onChange, onTouch } = props;
    const ids = useFieldIds(field, problem);
    if (field.readOnly) {
        return <ReadOnlyField field={field} text={readable(field, value, options)} />;
    }
    return (
        <FieldFrame field={field} ids={ids} problem={problem}>
            <TextField
                {...ids.control}
                type={type ?? 'text'}
                inputMode={inputMode}
                placeholder={placeholder}
                disabled={disabled}
                value={textOf(value)}
                onChange={(event) => onChange({ kind, value: event.target.value })}
                onBlur={onTouch}
            />
        </FieldFrame>
    );
}

export const TextLineField = (props: Readonly<FieldProps>) => <Line {...props} kind="text" placeholder={strings.enterText} />;
export const IntegerField = (props: Readonly<FieldProps>) => (
    <Line {...props} kind="integer" inputMode="numeric" placeholder={strings.wholeNumber} />
);
export const FloatField = (props: Readonly<FieldProps>) => (
    <Line {...props} kind="float" inputMode="decimal" placeholder={strings.number} />
);
export const DateField = (props: Readonly<FieldProps>) => <Line {...props} kind="date" type="date" />;
export const TimeField = (props: Readonly<FieldProps>) => <Line {...props} kind="time" type="time" />;

/** A date and time: the input shows what the person means, ILM is given it with the offset of this computer. */
export function DateTimeField({ field, value, options, problem, disabled, onChange, onTouch }: Readonly<FieldProps>) {
    const ids = useFieldIds(field, problem);
    if (field.readOnly) {
        return <ReadOnlyField field={field} text={readable(field, value, options)} />;
    }
    return (
        <FieldFrame field={field} ids={ids} problem={problem}>
            <TextField
                {...ids.control}
                type="datetime-local"
                disabled={disabled}
                value={toLocalInput(textOf(value))}
                onChange={(event) => onChange({ kind: 'dateTime', value: fromLocalInput(event.target.value) })}
                onBlur={onTouch}
            />
        </FieldFrame>
    );
}

export function TextAreaField({ field, value, problem, disabled, onChange, onTouch }: Readonly<FieldProps>) {
    const ids = useFieldIds(field, problem);
    if (field.readOnly) {
        return <ReadOnlyField field={field} text={textOf(value)} />;
    }
    return (
        <FieldFrame field={field} ids={ids} problem={problem}>
            <textarea
                {...ids.control}
                rows={4}
                placeholder={strings.enterText}
                disabled={disabled}
                value={textOf(value)}
                onChange={(event) => onChange({ kind: 'text', value: event.target.value })}
                onBlur={onTouch}
                className={areaClass}
            />
        </FieldFrame>
    );
}

/** A secret is hidden as it is typed; the button shows it while the person checks what they typed. */
export function SecretField({ field, value, options, problem, disabled, onChange, onTouch }: Readonly<FieldProps>) {
    const ids = useFieldIds(field, problem);
    const [shown, setShown] = useState(false);
    if (field.readOnly) {
        return <ReadOnlyField field={field} text={readable(field, value, options)} />;
    }
    const Icon = shown ? HideIcon : ShowIcon;
    return (
        <FieldFrame field={field} ids={ids} problem={problem}>
            <span className="relative flex items-center">
                <TextField
                    {...ids.control}
                    type={shown ? 'text' : 'password'}
                    autoComplete="off"
                    placeholder={strings.enterSecret}
                    disabled={disabled}
                    value={textOf(value)}
                    onChange={(event) => onChange({ kind: 'text', value: event.target.value })}
                    onBlur={onTouch}
                    className="pr-s5"
                />
                <button
                    type="button"
                    tabIndex={0}
                    aria-label={strings.showSecret}
                    aria-pressed={shown}
                    aria-controls={ids.id}
                    disabled={disabled}
                    onClick={() => setShown(!shown)}
                    className="absolute right-s2 text-secondary disabled:opacity-disabled"
                >
                    <Icon aria-hidden className="size-icon" />
                </button>
            </span>
        </FieldFrame>
    );
}
