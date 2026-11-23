import type { AttributeFieldView, AttributeOptionView, AttributeValue, FormValues } from '../../bridge';
import { strings } from '../../strings';

/** The text a text-like value holds; empty when there is none. */
export function textOf(value: AttributeValue | undefined): string {
    return value && 'value' in value && typeof value.value === 'string' ? value.value : '';
}

/** Whether the value says nothing: nothing typed, nothing chosen. */
export function isEmpty(value: AttributeValue | undefined): boolean {
    if (!value) {
        return true;
    }
    if (value.kind === 'options') {
        return value.value.length === 0;
    }
    return typeof value.value === 'string' && value.value.trim() === '';
}

/** The value ILM gives a field: none for a field without a control. */
export function givenValue(field: AttributeFieldView): AttributeValue | null {
    return field.kind && field.kind !== 'info' && !field.hidden ? field.value : null;
}

/** An empty values map without a prototype, so that a name like `__proto__` or `constructor` is an ordinary key. */
const noValues = (): FormValues => Object.create(null) as FormValues;

/** What a form starts with: the definition's own value of every field that has a control. */
export function initialValues(fields: AttributeFieldView[]): FormValues {
    const values = noValues();
    for (const field of fields) {
        const value = givenValue(field);
        if (value) {
            values[field.name] = value;
        }
    }
    return values;
}

/** The values with this one set, or removed when there is none; the same object when nothing changes. */
export function withValue(values: FormValues, name: string, value: AttributeValue | null | undefined): FormValues {
    const current = values[name];
    if (value == null ? current === undefined : current !== undefined && JSON.stringify(current) === JSON.stringify(value)) {
        return values;
    }
    const next = Object.assign(noValues(), values);
    if (value == null) {
        delete next[name];
    } else {
        next[name] = value;
    }
    return next;
}

/** The revision at which the field last moved, by its options, content or value; what a pending file read is held against. */
export function movedAt(field: AttributeFieldView): number {
    return Math.max(field.changedAt, field.valueSetAt);
}

/** The values without the choices of this field that its options no longer offer; the same object when all are offered. */
export function withoutGoneOptions(values: FormValues, field: AttributeFieldView): FormValues {
    const value = values[field.name];
    if (field.kind !== 'select' && field.kind !== 'multiselect') {
        return values;
    }
    const offered = (item: AttributeValue) => item.kind !== 'option' || field.options.some((option) => option.key === item.value);
    if (value?.kind === 'option') {
        return offered(value) ? values : withValue(values, field.name, null);
    }
    if (value?.kind === 'options') {
        const kept = value.value.filter(offered);
        if (kept.length === value.value.length) {
            return values;
        }
        return withValue(values, field.name, kept.length ? { kind: 'options', value: kept } : null);
    }
    return values;
}

const wallClock = /^(\d{4}-\d\d-\d\dT\d\d:\d\d)(?::(\d\d))?/;

const withOffset = /^(\d{4}-\d\d-\d\dT\d\d:\d\d)(:\d\d)?(\.\d+)?(Z|[+-]\d\d(?::?\d\d)?)$/i;
const pad = (number: number) => String(number).padStart(2, '0');

/**
 * The part of an ILM date and time that a `datetime-local` input shows: a value with an offset in this computer's time,
 * one without as it is written.
 */
export function toLocalInput(value: string): string {
    const zoned = withOffset.exec(value);
    if (zoned) {
        const [, minute, seconds, fraction, zone = ''] = zoned;
        const offset = zone.replace(/^([+-]\d\d)(?::?(\d\d))?$/, '$1:$2').replace(/:$/, ':00');
        const at = new Date(`${minute}${seconds ?? ':00'}${fraction ?? ''}${offset}`);
        if (!Number.isNaN(at.getTime())) {
            const day = `${at.getFullYear()}-${pad(at.getMonth() + 1)}-${pad(at.getDate())}`;
            const second = seconds === undefined ? '' : `:${pad(at.getSeconds())}`;
            return `${day}T${pad(at.getHours())}:${pad(at.getMinutes())}${second}`;
        }
    }
    return wallClock.exec(value)?.[0] ?? '';
}

/** The value of a `datetime-local` input as ILM takes it: with seconds, milliseconds and the offset of this computer. */
export function fromLocalInput(local: string): string {
    const parts = wallClock.exec(local);
    if (!parts) {
        return '';
    }
    const at = new Date(local);
    const valid = !Number.isNaN(at.getTime());
    const minutes = valid ? -at.getTimezoneOffset() : 0;
    const offset = `${minutes < 0 ? '-' : '+'}${pad(Math.trunc(Math.abs(minutes) / 60))}:${pad(Math.abs(minutes) % 60)}`;
    if (!valid) {
        return `${parts[1]}:${parts[2] ?? '00'}.000${offset}`;
    }
    // A time the clock skips (daylight saving) moves on: the fields come from the date that carries the offset.
    const day = `${at.getFullYear()}-${pad(at.getMonth() + 1)}-${pad(at.getDate())}`;
    return `${day}T${pad(at.getHours())}:${pad(at.getMinutes())}:${pad(at.getSeconds())}.000${offset}`;
}

/** The bytes a base64 text stands for. */
export function base64Size(content: string): number {
    let padding = 0;
    if (content.endsWith('==')) {
        padding = 2;
    } else if (content.endsWith('=')) {
        padding = 1;
    }
    return Math.floor((content.length * 3) / 4) - padding;
}

const when = (text: string, options: Intl.DateTimeFormatOptions, shown = text) => {
    const at = new Date(text);
    return Number.isNaN(at.getTime()) ? shown : new Intl.DateTimeFormat(undefined, options).format(at);
};

/** A value as plain text, for a field that cannot be changed. */
export function readable(field: AttributeFieldView, value: AttributeValue | undefined, options: AttributeOptionView[]): string {
    if (!value) {
        return '';
    }
    switch (value.kind) {
        case 'option':
            return options.find((option) => option.key === value.value)?.label ?? '';
        case 'options':
            return value.value
                .map((item) => readable(field, item, options))
                .filter(Boolean)
                .join(', ');
        case 'added':
            return readable(field, value.value, options);
        case 'bool':
            return value.value ? strings.switchOn : strings.switchOff;
        case 'file':
            return strings.fileDescription(value.value.name, base64Size(value.value.content));
        case 'date':
            return when(`${value.value}T00:00`, { dateStyle: 'medium' }, value.value);
        case 'dateTime':
            return when(toLocalInput(value.value), { dateStyle: 'medium', timeStyle: 'short' });
        case 'time':
            return value.value.slice(0, 5);
        default:
            return field.kind === 'secret' ? '\u2022'.repeat(12) : String(value.value);
    }
}
