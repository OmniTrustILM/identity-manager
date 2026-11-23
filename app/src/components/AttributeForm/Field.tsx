import { type ReactNode, useId } from 'react';
import type { AttributeFieldView, AttributeOptionView, AttributeValue } from '../../bridge';
import { LockIcon } from '../../design-system/icons';
import { strings } from '../../strings';

/** What every field component is given; `onChange` with nothing clears the value. */
export interface FieldProps {
    field: AttributeFieldView;
    value: AttributeValue | undefined;
    options: AttributeOptionView[];
    /** The words for what is wrong with the value, once the person has been to the field. */
    problem: string | null;
    disabled: boolean;
    /** When the form last changed the field, read now: a value the control prepared since is void if this moved on. */
    changedAt: () => number;
    /** A value the control prepared asynchronously passes the `changedAt` it began under, and is dropped if the form has moved on. */
    onChange: (value: AttributeValue | undefined, changedAt?: number) => void;
    /** The person is done with the field. */
    onTouch: () => void;
    /** The control is still preparing the value, so the form is not fit to be sent. */
    onBusy: (busy: boolean) => void;
}

/** The ids that tie a field's label, description and problem to its control. */
export function useFieldIds(field: AttributeFieldView, problem: string | null) {
    const id = useId();
    const hint = field.description || field.constraints.some((constraint) => strings.attributeConstraint(constraint)) ? `${id}-hint` : null;
    const problemId = problem ? `${id}-problem` : null;
    return {
        id,
        labelId: `${id}-label`,
        hintId: hint,
        problemId,
        /** The attributes a control takes to be named, required and described by its field. */
        control: {
            id,
            'aria-required': field.required || undefined,
            'aria-invalid': problem ? true : undefined,
            'aria-describedby': [hint, problemId].filter(Boolean).join(' ') || undefined,
        },
    };
}

type Ids = ReturnType<typeof useFieldIds>;

/**
 * The label, the lock of a read-only field, the line of what the definition asks, the control and the problem of one field.
 * A group of controls is named by a legend instead of a label.
 */
export function FieldFrame({
    field,
    ids,
    problem,
    group = false,
    spoken = group,
    aside,
    children,
}: Readonly<{
    field: AttributeFieldView;
    ids: Ids;
    problem: string | null;
    group?: boolean;
    spoken?: boolean;
    aside?: ReactNode;
    children: ReactNode;
}>) {
    const marks = (
        <>
            {field.required && (
                <>
                    <span aria-hidden className="text-bad">
                        *
                    </span>
                    {spoken && <span className="sr-only">{strings.attributeRequired}</span>}
                </>
            )}
            {field.readOnly && <LockIcon role="img" aria-label={strings.attributeReadOnly} className="size-icon shrink-0" />}
        </>
    );
    const label = 'flex items-center gap-s1 text-caption font-semibold text-secondary';
    const hints = [field.description, ...field.constraints.map((constraint) => strings.attributeConstraint(constraint))].filter(Boolean);
    const body = (
        <>
            {ids.hintId && (
                <p id={ids.hintId} className="text-caption text-secondary">
                    {hints.join(' ')}
                </p>
            )}
            {children}
            {problem && (
                <p id={ids.problemId ?? undefined} role="alert" className="text-caption text-bad">
                    {problem}
                </p>
            )}
        </>
    );
    const head = (content: ReactNode) => (
        <div className="flex items-baseline justify-between gap-s2">
            {content}
            {aside}
        </div>
    );
    if (group) {
        return (
            <fieldset aria-describedby={ids.control['aria-describedby']} className="m-0 flex min-w-0 flex-col gap-s1 border-0 p-0">
                <legend className={`${label} p-0`}>
                    {field.label}
                    {marks}
                </legend>
                {body}
            </fieldset>
        );
    }
    return (
        <div className="flex flex-col gap-s1">
            {head(
                <label id={ids.labelId} htmlFor={ids.id} className={label}>
                    {field.label}
                    {marks}
                </label>,
            )}
            {body}
        </div>
    );
}

/** A field that cannot be changed: its label with the lock, then the value as plain text. */
export function ReadOnlyField({ field, text, mono = false }: Readonly<{ field: AttributeFieldView; text: string; mono?: boolean }>) {
    return (
        <fieldset className="m-0 flex min-w-0 flex-col gap-s1 border-0 p-0">
            <legend className="flex items-center gap-s1 p-0 text-caption font-semibold text-secondary">
                {field.label}
                {field.required && (
                    <span aria-hidden className="text-bad">
                        *
                    </span>
                )}
                <LockIcon role="img" aria-label={strings.attributeReadOnly} className="size-icon shrink-0" />
            </legend>
            <p
                className={`whitespace-pre-wrap break-words text-body text-primary ${mono ? 'rounded-control bg-button px-s3 py-s2 font-mono' : ''}`}
            >
                {text}
            </p>
        </fieldset>
    );
}

export const inputClass =
    'w-full rounded-control border border-input-edge bg-input px-s3 text-body text-primary placeholder:text-tertiary disabled:opacity-disabled aria-invalid:border-bad';
export const areaClass = `${inputClass} py-s2`;
