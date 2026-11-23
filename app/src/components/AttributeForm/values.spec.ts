import { expect, test } from 'vitest';
import type { AttributeFieldView, AttributeValue, FormValues } from '../../bridge';
import { strings } from '../../strings';
import {
    base64Size,
    fromLocalInput,
    givenValue,
    initialValues,
    isEmpty,
    readable,
    textOf,
    toLocalInput,
    withoutGoneOptions,
    withValue,
} from './values';

const field = (over: Partial<AttributeFieldView> = {}): AttributeFieldView => ({
    name: 'f',
    label: 'F',
    description: null,
    kind: 'textline',
    required: false,
    readOnly: false,
    hidden: false,
    extensible: false,
    valueKind: null,
    options: [],
    value: null,
    language: null,
    constraints: [],
    callback: { kind: 'none' },
    changedAt: 0,
    resetAt: 0,
    valueSetAt: 0,
    ...over,
});
const text = (value: string): AttributeValue => ({ kind: 'text', value });

test('a form starts with the values of its fields that have a control', () => {
    const values = initialValues([
        field({ name: 'a', value: text('x') }),
        field({ name: 'hidden', hidden: true, value: text('y') }),
        field({ name: 'info', kind: 'info', value: text('note') }),
        field({ name: 'none', kind: null, value: text('z') }),
        field({ name: 'empty' }),
    ]);

    expect(values).toEqual({ a: text('x') });
});

test('setting a value to what it already is changes nothing, and nothing removes it', () => {
    const values = { a: text('x') };

    expect(withValue(values, 'a', text('x'))).toBe(values);
    expect(withValue(values, 'b', null)).toBe(values);
    expect(withValue(values, 'a', text('y'))).toEqual({ a: text('y') });
    expect(withValue(values, 'a', undefined)).toEqual({});
    expect(withValue(values, 'b', text('1'))).toEqual({ a: text('x'), b: text('1') });
});

test.each([
    [undefined, true],
    [text(''), true],
    [text('  '), true],
    [text('a'), false],
    [{ kind: 'options', value: [] } as AttributeValue, true],
    [{ kind: 'options', value: [{ kind: 'option', value: 'k0' }] } as AttributeValue, false],
    [{ kind: 'bool', value: false } as AttributeValue, false],
    [{ kind: 'option', value: 'k0' } as AttributeValue, false],
])('%j is empty: %s', (value, empty) => {
    expect(isEmpty(value)).toBe(empty);
});

test('the text of a value is empty when it holds none', () => {
    expect(textOf(text('a'))).toBe('a');
    expect(textOf({ kind: 'bool', value: true })).toBe('');
    expect(textOf(undefined)).toBe('');
});

test('a date and time without an offset keeps its wall clock for the input and gains this computer’s offset', () => {
    expect(toLocalInput('2026-11-23T14:30:00.000')).toBe('2026-11-23T14:30:00');
    expect(toLocalInput('2026-11-23T14:30')).toBe('2026-11-23T14:30');
    expect(toLocalInput('nonsense')).toBe('');

    const sent = fromLocalInput('2026-11-23T14:30');
    const minutes = -new Date('2026-11-23T14:30').getTimezoneOffset();
    const offset = `${minutes < 0 ? '-' : '+'}${String(Math.floor(Math.abs(minutes) / 60)).padStart(2, '0')}:${String(Math.abs(minutes) % 60).padStart(2, '0')}`;
    expect(sent).toBe(`2026-11-23T14:30:00.000${offset}`);
    expect(fromLocalInput('2026-11-23T14:30:15')).toContain('T14:30:15.000');
    expect(fromLocalInput('')).toBe('');
});

/** Runs the check with the computer in India (+05:30, no daylight saving), so that no default is its own local time. */
const inIndia = (check: () => void) => {
    const before = process.env.TZ;
    process.env.TZ = 'Asia/Kolkata';
    try {
        check();
    } finally {
        if (before === undefined) {
            delete process.env.TZ;
        } else {
            process.env.TZ = before;
        }
    }
};

test('a date and time with an offset is shown in this computer’s time and edited without moving the instant', () => {
    inIndia(() => {
        expect(toLocalInput('2026-11-23T14:30:00.000Z')).toBe('2026-11-23T20:00:00');
        expect(toLocalInput('2026-11-23T14:30:00.000+01:00')).toBe('2026-11-23T19:00:00');
        expect(toLocalInput('2026-11-23T14:30:00+0100')).toBe('2026-11-23T19:00:00');
        expect(toLocalInput('2026-11-23T14:30Z')).toBe('2026-11-23T20:00');
        expect(toLocalInput('2026-11-23T23:50:00.000Z')).toBe('2026-11-24T05:20:00');

        const edited = fromLocalInput('2026-11-23T20:01');
        expect(edited).toBe('2026-11-23T20:01:00.000+05:30');
        expect(new Date(edited).getTime() - new Date('2026-11-23T14:30:00.000Z').getTime()).toBe(60_000);
    });
});

test('a date and time with an offset is read in this computer’s time', () => {
    inIndia(() => {
        const text = readable(field({ kind: 'datetime' }), { kind: 'dateTime', value: '2026-11-23T14:30:00.000Z' }, []);
        expect(text).toBe(
            new Intl.DateTimeFormat(undefined, { dateStyle: 'medium', timeStyle: 'short' }).format(new Date('2026-11-23T14:30:00.000Z')),
        );
        expect(text).toContain('8:00');
    });
});

test.each([
    ['', 0],
    ['YQ==', 1],
    ['YWI=', 2],
    ['YWJj', 3],
])('base64 %j stands for %i bytes', (content, size) => {
    expect(base64Size(content)).toBe(size);
});

test('a value is read as plain text for a field that cannot be changed', () => {
    const options = [
        { key: 'k0', label: 'Engineering' },
        { key: 'k1', label: 'IT' },
    ];
    const read = (value: AttributeValue | undefined, over: Partial<AttributeFieldView> = {}) => readable(field(over), value, options);

    expect(read(undefined)).toBe('');
    expect(read({ kind: 'option', value: 'k1' })).toBe('IT');
    expect(read({ kind: 'option', value: 'gone' })).toBe('');
    expect(
        read({
            kind: 'options',
            value: [
                { kind: 'option', value: 'k0' },
                { kind: 'added', value: text('Ops') },
            ],
        }),
    ).toBe('Engineering, Ops');
    expect(read({ kind: 'bool', value: true })).toBe(strings.switchOn);
    expect(read({ kind: 'bool', value: false })).toBe(strings.switchOff);
    expect(read({ kind: 'file', value: { name: 'a.csr', mime: 'text/plain', content: 'YWJj' } })).toBe('a.csr, 3 B');
    expect(read({ kind: 'date', value: '2026-11-23' })).toBe(strings.date(new Date(2026, 10, 23).getTime()));
    expect(read({ kind: 'date', value: 'x' })).toBe('x');
    expect(read({ kind: 'dateTime', value: '2026-11-23T14:30:00.000' })).toBe(
        new Intl.DateTimeFormat(undefined, { dateStyle: 'medium', timeStyle: 'short' }).format(new Date(2026, 10, 23, 14, 30)),
    );
    expect(read({ kind: 'time', value: '14:30:00' })).toBe('14:30');
    expect(read(text('secret'), { kind: 'secret' })).toBe('•'.repeat(12));
    expect(read({ kind: 'integer', value: '42' })).toBe('42');
});

test('the value ILM gives a field is none for a field without a control', () => {
    expect(givenValue(field({ value: text('x') }))).toEqual(text('x'));
    expect(givenValue(field({ value: text('x'), hidden: true, kind: null }))).toBeNull();
    expect(givenValue(field({ value: text('x'), kind: 'info' }))).toBeNull();
    expect(givenValue(field({ value: null }))).toBeNull();
});

test('the choices of a list that its options no longer offer go, and the rest stay', () => {
    const list = field({
        name: 'l',
        kind: 'select',
        options: [
            { key: 'a', label: 'A' },
            { key: 'b', label: 'B' },
        ],
    });
    const many = { ...list, kind: 'multiselect' } as AttributeFieldView;
    const added = { kind: 'added', value: text('mine') } as const;
    const values = { l: { kind: 'option', value: 'a' } } as FormValues;

    expect(withoutGoneOptions(values, list)).toBe(values);
    expect(withoutGoneOptions(values, { ...list, options: [] })).toEqual({});
    const chosen = { l: { kind: 'options', value: [{ kind: 'option', value: 'a' }, { kind: 'option', value: 'z' }, added] } } as FormValues;
    expect(withoutGoneOptions(chosen, many)).toEqual({ l: { kind: 'options', value: [{ kind: 'option', value: 'a' }, added] } });
    expect(withoutGoneOptions({ l: { kind: 'options', value: [{ kind: 'option', value: 'z' }] } }, many)).toEqual({});
    expect(withoutGoneOptions(values, field({ name: 'l', kind: 'textline' }))).toBe(values);
    expect(withoutGoneOptions({}, list)).toEqual({});
});
