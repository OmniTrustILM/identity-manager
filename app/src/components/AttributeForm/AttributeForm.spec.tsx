import { clearMocks, mockIPC } from '@tauri-apps/api/mocks';
import { act } from 'react';
import { createRoot, type Root } from 'react-dom/client';
import { afterEach, beforeEach, expect, test, vi } from 'vitest';
import type { AttributeCallbackResult, AttributeFieldProblem, AttributeFieldView, AttributeFormView, AttributeValue } from '../../bridge';
import { strings } from '../../strings';
import { AttributeForm, type AttributeState, callbackDelay, checkDelay } from './AttributeForm';
import { toLocalInput } from './values';

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
const form = (fields: AttributeFieldView[], over: Partial<AttributeFormView> = {}): AttributeFormView => ({
    id: 'form-1',
    revision: 0,
    groups: [{ title: null, fields }],
    unsupported: [],
    web: null,
    ...over,
});
const text = (value: string): AttributeValue => ({ kind: 'text', value });
const levels = [
    { key: 'k0', label: 'Low' },
    { key: 'k1', label: 'Medium' },
    { key: 'k2', label: 'High' },
];

/** The reply of the core to a callback run: the form as it is, and what ILM said if it gave no answer. */
const reply = (call: { field: string; seq: number }, next: AttributeFormView, problem: string | null = null): AttributeCallbackResult => ({
    seq: call.seq,
    field: call.field,
    form: next,
    problem,
});

type Asked = { field: string; seq: number; values: Record<string, AttributeValue> };

let container: HTMLElement;
let root: Root;
let problems: AttributeFieldProblem[];
/** The revision of the form the core says its checks were made against. */
let coreRevision: number;
/** The snapshot drawn at first; a run that changed nothing answers with it. */
let shown: AttributeFormView;
let checks: Record<string, AttributeValue>[];
let asked: Asked[];
let answer: (call: Asked) => AttributeCallbackResult | Promise<AttributeCallbackResult>;
let opened: unknown[];
let openRefused: boolean;
let states: AttributeState[];
const remember = (state: AttributeState) => states.push(state);
const last = () => states.at(-1) as AttributeState;

const wait = (ms: number) =>
    act(async () => {
        await vi.advanceTimersByTimeAsync(ms);
    });

beforeEach(() => {
    (globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true;
    vi.useFakeTimers();
    container = document.createElement('div');
    document.body.append(container);
    root = createRoot(container);
    problems = [];
    coreRevision = 0;
    checks = [];
    asked = [];
    opened = [];
    openRefused = false;
    states = [];
    answer = ({ field: name, seq }) => reply({ field: name, seq }, shown);
    mockIPC((command, args) => {
        const given = args as { values: Record<string, AttributeValue>; field: string; seq: number };
        switch (command) {
            case 'check_attributes':
                checks.push(given.values);
                return { revision: coreRevision, problems };
            case 'attribute_callback': {
                const call = { field: given.field, seq: given.seq, values: given.values };
                asked.push(call);
                return answer(call);
            }
            case 'open_in_ilm':
                opened.push(args);
                return openRefused ? Promise.reject('no') : undefined;
            default:
                return undefined;
        }
    });
});

afterEach(async () => {
    await act(async () => root.unmount());
    container.remove();
    clearMocks();
    vi.useRealTimers();
});

const render = async (view: AttributeFormView, props: Partial<React.ComponentProps<typeof AttributeForm>> = {}) => {
    shown = view;
    coreRevision = view.revision;
    await act(async () => root.render(<AttributeForm form={view} target="addToIlm" onChange={remember} {...props} />));
    await wait(0);
};

const control = (label: string) => {
    const candidate = [...container.querySelectorAll('label')].find((item) => item.textContent?.startsWith(label));
    return container.querySelector(`[id="${candidate?.htmlFor}"]`) as HTMLInputElement & HTMLTextAreaElement & HTMLSelectElement;
};
const group = (label: string) =>
    [...container.querySelectorAll('fieldset')].find((item) =>
        item.querySelector('legend')?.textContent?.startsWith(label),
    ) as HTMLFieldSetElement;
const button = (name: string) =>
    [...container.querySelectorAll('button')].find((item) => item.textContent === name || item.getAttribute('aria-label') === name);
const describedBy = (element: Element) =>
    (element.getAttribute('aria-describedby') ?? '')
        .split(' ')
        .filter(Boolean)
        .map((id) => document.getElementById(id)?.textContent)
        .join('|');

const typeInto = (element: HTMLInputElement | HTMLTextAreaElement, value: string) =>
    act(async () => {
        const prototype = element instanceof HTMLTextAreaElement ? HTMLTextAreaElement.prototype : HTMLInputElement.prototype;
        Object.getOwnPropertyDescriptor(prototype, 'value')?.set?.call(element, value);
        element.dispatchEvent(new Event('input', { bubbles: true }));
    });
const leave = (element: Element) =>
    act(async () => {
        element.dispatchEvent(new FocusEvent('focusout', { bubbles: true }));
    });
const click = (element: Element | undefined) => act(async () => (element as HTMLElement).click());
const choose = (select: HTMLSelectElement, value: string) =>
    act(async () => {
        select.value = value;
        select.dispatchEvent(new Event('change', { bubbles: true }));
    });

test('every field has a label tied to its control, a required mark and the words of its description', async () => {
    await render(
        form([
            field({ name: 'owner', label: 'Owner', required: true, description: 'Who looks after it' }),
            field({ name: 'note', label: 'Note', kind: 'textarea' }),
            field({
                name: 'size',
                label: 'Size',
                kind: 'integer',
                constraints: [{ kind: 'range', min: 1, max: 9 }],
            }),
        ]),
    );

    const owner = control('Owner');
    expect(owner.getAttribute('aria-required')).toBe('true');
    expect(owner.type).toBe('text');
    expect(container.querySelector('label[for]')?.querySelector('[aria-hidden]')?.textContent).toBe('*');
    expect(describedBy(owner)).toBe('Who looks after it');
    expect(control('Note').tagName).toBe('TEXTAREA');
    expect(control('Note').getAttribute('rows')).toBe('4');
    expect(control('Note').getAttribute('aria-required')).toBeNull();
    expect(control('Size').inputMode).toBe('numeric');
    expect(describedBy(control('Size'))).toBe('From 1 to 9');
});

test('typing gives the typed text, as text, a whole number or a number', async () => {
    await render(
        form([
            field({ name: 'a', label: 'A' }),
            field({ name: 'i', label: 'I', kind: 'integer' }),
            field({ name: 'x', label: 'X', kind: 'float' }),
            field({ name: 'n', label: 'N', kind: 'textarea' }),
        ]),
    );

    await typeInto(control('A'), 'Alex');
    await typeInto(control('I'), '4 2');
    await typeInto(control('X'), '0,7,5');
    await typeInto(control('N'), 'one\ntwo');

    expect(last().values).toEqual({
        a: text('Alex'),
        i: { kind: 'integer', value: '4 2' },
        x: { kind: 'float', value: '0,7,5' },
        n: text('one\ntwo'),
    });
    expect(control('X').inputMode).toBe('decimal');
});

test('a secret is hidden until the person shows it', async () => {
    await render(form([field({ name: 's', label: 'API key', kind: 'secret', required: true })]));
    const input = control('API key');

    expect(input.type).toBe('password');
    expect(input.autocomplete).toBe('off');
    await typeInto(input, 'hunter22');
    const show = button(strings.showSecret) as HTMLButtonElement;
    expect(show.getAttribute('aria-pressed')).toBe('false');
    await click(show);

    expect(input.type).toBe('text');
    expect(show.getAttribute('aria-pressed')).toBe('true');
    expect(last().values).toEqual({ s: text('hunter22') });
});

test('a switch starts as defined, reports the change and tells On or Off', async () => {
    await render(form([field({ name: 'b', label: 'Notify owner', kind: 'switch', value: { kind: 'bool', value: false } })]));
    const toggle = control('Notify owner');

    expect(toggle.getAttribute('role')).toBe('switch');
    expect(container.textContent).toContain(strings.switchOff);
    await click(toggle);

    expect(last().values).toEqual({ b: { kind: 'bool', value: true } });
    expect(container.textContent).toContain(strings.switchOn);
});

test('date, time and date and time take the native inputs and the date and time gains an offset', async () => {
    await render(
        form([
            field({ name: 'd', label: 'Review date', kind: 'date' }),
            field({ name: 't', label: 'Window start', kind: 'time' }),
            field({
                name: 'dt',
                label: 'Valid until',
                kind: 'datetime',
                value: { kind: 'dateTime', value: '2026-11-23T14:30:00.000+01:00' },
            }),
        ]),
    );

    expect(control('Review date').type).toBe('date');
    expect(control('Window start').type).toBe('time');
    expect(control('Valid until').type).toBe('datetime-local');
    expect(control('Valid until').value).toBe(toLocalInput('2026-11-23T14:30:00.000+01:00').slice(0, 16));
    await typeInto(control('Review date'), '2026-11-24');
    await typeInto(control('Window start'), '09:15');
    await typeInto(control('Valid until'), '2026-12-01T08:00');

    const values = last().values;
    expect(values.d).toEqual({ kind: 'date', value: '2026-11-24' });
    expect(values.t).toEqual({ kind: 'time', value: '09:15' });
    expect(values.dt).toEqual({ kind: 'dateTime', value: expect.stringMatching(/^2026-12-01T08:00:00\.000[+-]\d\d:\d\d$/) });
});

/** FileReader is not driven by the fake timers, so the clock is the real one while it reads. */
const choosing = async (name: string, size: number, type = 'text/plain') => {
    vi.useRealTimers();
    const input = container.querySelector('input[type="file"]') as HTMLInputElement;
    const file = new File(['a'.repeat(size)], name, { type });
    Object.defineProperty(input, 'files', { configurable: true, value: [file] });
    await act(async () => {
        input.dispatchEvent(new Event('change', { bubbles: true }));
    });
    await act(async () => {
        await new Promise((resolve) => setTimeout(resolve, 30));
    });
};

test('a file is read as base64 and shown by its name and size; the button is named by the label', async () => {
    await render(form([field({ name: 'f', label: 'Template', kind: 'file' })]));
    const chooser = button(strings.chooseFile) as HTMLButtonElement;
    const clicks = vi.spyOn(container.querySelector('input[type="file"]') as HTMLInputElement, 'click');

    expect(container.textContent).toContain(strings.noFileChosen);
    expect(document.getElementById(chooser.getAttribute('aria-labelledby')?.split(' ')[0] ?? '')?.textContent).toBe('Template');
    await click(chooser);
    expect(clicks).toHaveBeenCalled();
    await choosing('client.csr', 2400, '');

    expect(last().values.f).toEqual({
        kind: 'file',
        value: { name: 'client.csr', mime: 'application/octet-stream', content: btoa('a'.repeat(2400)) },
    });
    expect(container.textContent).toContain('client.csr');
    expect(container.textContent).toContain('2.3 KB');
    expect(container.textContent).not.toContain(strings.noFileChosen);
});

test('a file over 1 MiB is refused with its words, and none is kept', async () => {
    await render(form([field({ name: 'f', label: 'Template', kind: 'file', required: true })]));

    await choosing('big.bin', 1024 * 1024 + 1);

    expect(last().values.f).toBeUndefined();
    const chooser = button(strings.chooseFile) as HTMLButtonElement;
    expect(describedBy(chooser)).toBe(strings.attributeProblem({ kind: 'fileTooLarge', max: 1048576 }, 'file'));
    expect(chooser.parentElement?.getAttribute('aria-invalid')).toBe('true');
});

/** A FileReader the test finishes by hand, in any order. */
const slowReads = () => {
    const readers: { finish: (content: string) => void; fail: () => void }[] = [];
    class SlowReader {
        result: string | null = null;
        onload: (() => void) | null = null;
        onerror: (() => void) | null = null;
        readAsDataURL() {
            readers.push({
                finish: (content) => {
                    this.result = `data:text/plain;base64,${content}`;
                    this.onload?.();
                },
                fail: () => this.onerror?.(),
            });
        }
    }
    vi.stubGlobal('FileReader', SlowReader);
    return readers;
};
const selecting = async (name: string) => {
    const input = container.querySelector('input[type="file"]') as HTMLInputElement;
    Object.defineProperty(input, 'files', { configurable: true, value: [new File(['x'], name, { type: 'text/plain' })] });
    await act(async () => {
        input.dispatchEvent(new Event('change', { bubbles: true }));
    });
};

test('the form is not ready while a chosen file is being read', async () => {
    const readers = slowReads();
    await render(form([field({ name: 'f', label: 'Template', kind: 'file' })]));
    await wait(checkDelay);
    expect(last().ready).toBe(true);

    await selecting('a.csr');
    await wait(checkDelay);
    expect(last().ready).toBe(false);

    await act(async () => readers[0]?.finish('QQ=='));
    await wait(checkDelay);
    expect(last().ready).toBe(true);
    expect(last().values.f).toEqual({ kind: 'file', value: { name: 'a.csr', mime: 'text/plain', content: 'QQ==' } });
    vi.unstubAllGlobals();
});

test('a read that is overtaken by a later choice is ignored', async () => {
    const readers = slowReads();
    await render(form([field({ name: 'f', label: 'Template', kind: 'file' })]));

    await selecting('old.csr');
    await selecting('new.csr');
    await act(async () => readers[1]?.finish('bmV3'));
    await act(async () => readers[0]?.finish('b2xk'));
    await wait(checkDelay);

    expect(last().values.f).toEqual({ kind: 'file', value: { name: 'new.csr', mime: 'text/plain', content: 'bmV3' } });
    expect(last().ready).toBe(true);
    vi.unstubAllGlobals();
});

test('a file over 1 MiB chosen while another is being read supersedes it', async () => {
    const readers = slowReads();
    await render(form([field({ name: 'f', label: 'Template', kind: 'file' })]));
    await selecting('a.csr');
    const input = container.querySelector('input[type="file"]') as HTMLInputElement;
    Object.defineProperty(input, 'files', {
        configurable: true,
        value: [new File(['a'.repeat(1024 * 1024 + 1)], 'big.bin')],
    });
    await act(async () => {
        input.dispatchEvent(new Event('change', { bubbles: true }));
    });
    await act(async () => readers[0]?.finish('QQ=='));
    await wait(checkDelay);

    expect(last().values.f).toBeUndefined();
    vi.unstubAllGlobals();
});

test('no file chosen leaves the value alone', async () => {
    await render(form([field({ name: 'f', label: 'Template', kind: 'file' })]));
    const input = container.querySelector('input[type="file"]') as HTMLInputElement;
    Object.defineProperty(input, 'files', { configurable: true, value: [] });

    await act(async () => {
        input.dispatchEvent(new Event('change', { bubbles: true }));
    });

    expect(last().values.f).toBeUndefined();
});

test('code and JSON have monospaced areas and the code its language as a caption', async () => {
    await render(
        form([
            field({ name: 'c', label: 'Script', kind: 'code', language: 'bash' }),
            field({ name: 'j', label: 'Settings', kind: 'json' }),
        ]),
    );

    expect(control('Script').className).toContain('font-mono');
    expect(control('Script').placeholder).toBe(strings.enterScript);
    expect(container.textContent).toContain('bash');
    expect(control('Settings').placeholder).toBe(strings.enterJson);
    await typeInto(control('Script'), 'exit 0');
    await typeInto(control('Settings'), '{ "a": 1 }');

    expect(last().values).toEqual({ c: { kind: 'code', value: 'exit 0' }, j: { kind: 'object', value: '{ "a": 1 }' } });
});

test('a single select offers None when optional and Select once required, and reports the option by its key', async () => {
    await render(
        form([
            field({ name: 'o', label: 'Importance', kind: 'select', options: levels }),
            field({ name: 'r', label: 'Validity', kind: 'select', options: levels, required: true }),
        ]),
    );
    const optional = control('Importance');
    const needed = control('Validity');

    expect([...optional.options].map((option) => option.textContent)).toEqual([strings.none, 'Low', 'Medium', 'High']);
    expect([...needed.options].map((option) => option.textContent)).toEqual([strings.selectValue, 'Low', 'Medium', 'High']);
    expect(needed.getAttribute('aria-required')).toBe('true');
    await choose(optional, 'k1');
    await choose(needed, 'k2');
    expect(last().values).toEqual({ o: { kind: 'option', value: 'k1' }, r: { kind: 'option', value: 'k2' } });
    expect([...needed.options].map((option) => option.textContent)).toEqual(['Low', 'Medium', 'High']);

    await choose(optional, '');
    expect(last().values).toEqual({ r: { kind: 'option', value: 'k2' } });
});

test('a multi-select is a group of checkboxes, each one a value, and the keyboard toggles them', async () => {
    await render(form([field({ name: 'm', label: 'Department', kind: 'multiselect', options: levels, required: true })]));
    const boxes = () => [...group('Department').querySelectorAll<HTMLInputElement>('input[type="checkbox"]')];

    expect(group('Department').querySelector('legend')?.textContent).toContain(strings.attributeRequired);
    expect(boxes().map((box) => box.labels?.[0]?.textContent)).toEqual(['Low', 'Medium', 'High']);
    await click(boxes()[0]);
    await click(boxes()[2]);
    expect(last().values.m).toEqual({
        kind: 'options',
        value: [
            { kind: 'option', value: 'k0' },
            { kind: 'option', value: 'k2' },
        ],
    });
    await click(boxes()[0]);
    await click(boxes()[2]);

    expect(last().values.m).toBeUndefined();
    expect(boxes().every((box) => box.tabIndex === 0)).toBe(true);
});

test('an extensible list takes values the person adds, by the button or Enter, once each, and takes them away again', async () => {
    await render(
        form([
            field({
                name: 'e',
                label: 'Contacts',
                kind: 'multiselect',
                extensible: true,
                valueKind: 'text',
                options: [{ key: 'k0', label: 'ops@example.com' }],
                value: { kind: 'options', value: [{ kind: 'option', value: 'k0' }] },
            }),
        ]),
    );
    const add = control('Contacts') ?? null;
    expect(add).toBeNull();
    const input = container.querySelector(`input[aria-label="${strings.addValueTo('Contacts')}"]`) as HTMLInputElement;
    const plus = button(strings.add) as HTMLButtonElement;

    expect(input.placeholder).toBe(strings.addValue);
    expect(plus.disabled).toBe(true);
    await typeInto(input, '  sec@example.com ');
    await click(plus);
    await typeInto(input, 'sec@example.com');
    await act(async () => {
        input.dispatchEvent(new KeyboardEvent('keydown', { key: 'Enter', bubbles: true, cancelable: true }));
    });
    await typeInto(input, 'dev@example.com');
    await act(async () => {
        input.dispatchEvent(new KeyboardEvent('keydown', { key: 'Enter', bubbles: true, cancelable: true }));
    });

    expect(last().values.e).toEqual({
        kind: 'options',
        value: [
            { kind: 'option', value: 'k0' },
            { kind: 'added', value: text('sec@example.com') },
            { kind: 'added', value: text('dev@example.com') },
        ],
    });
    const boxes = [...group('Contacts').querySelectorAll<HTMLInputElement>('input[type="checkbox"]')];
    expect(boxes.map((box) => `${box.labels?.[0]?.textContent}:${box.checked}`)).toEqual([
        'ops@example.com:true',
        'sec@example.com:true',
        'dev@example.com:true',
    ]);
    expect(input.value).toBe('');

    await click(boxes[1]);
    expect(last().values.e).toEqual({
        kind: 'options',
        value: [
            { kind: 'option', value: 'k0' },
            { kind: 'added', value: text('dev@example.com') },
        ],
    });
});

test('a single list takes an added value, in the kind of input the list holds, and it becomes the chosen value', async () => {
    await render(
        form([
            field({
                name: 'n',
                label: 'Number',
                kind: 'select',
                extensible: true,
                valueKind: 'integer',
                options: [{ key: 'k0', label: '1' }],
            }),
            field({
                name: 'd',
                label: 'Day',
                kind: 'select',
                extensible: true,
                valueKind: 'date',
                options: [{ key: 'k0', label: '2026-01-01' }],
            }),
        ]),
    );
    const number = container.querySelector(`input[aria-label="${strings.addValueTo('Number')}"]`) as HTMLInputElement;
    const day = container.querySelector(`input[aria-label="${strings.addValueTo('Day')}"]`) as HTMLInputElement;

    expect(number.inputMode).toBe('numeric');
    expect(day.type).toBe('date');
    await typeInto(number, '42');
    await act(async () => {
        number.dispatchEvent(new KeyboardEvent('keydown', { key: 'Enter', bubbles: true, cancelable: true }));
    });
    await typeInto(day, '2026-02-03');
    await click(container.querySelectorAll<HTMLButtonElement>(`button[aria-label="${strings.add}"]`)[1]);

    expect(last().values).toEqual({
        n: { kind: 'added', value: { kind: 'integer', value: '42' } },
        d: { kind: 'added', value: { kind: 'date', value: '2026-02-03' } },
    });
    const select = control('Number');
    expect([...select.options].map((option) => option.textContent)).toEqual([strings.none, '1', '42']);
    expect(select.value).toBe('added');
    expect(number.value).toBe('');

    await choose(select, 'k0');
    expect(last().values.n).toEqual({ kind: 'option', value: 'k0' });
    expect([...select.options].map((option) => option.textContent)).toEqual([strings.none, '1']);
});

test('an added date and time of a list gains the offset of this computer, and a list of no typable kind adds nothing', async () => {
    await render(
        form([
            field({ name: 'm', label: 'Moment', kind: 'multiselect', extensible: true, valueKind: 'dateTime' }),
            field({ name: 'x', label: 'Other', kind: 'multiselect', extensible: true, valueKind: null }),
        ]),
    );
    const input = container.querySelector(`input[aria-label="${strings.addValueTo('Moment')}"]`) as HTMLInputElement;

    expect(input.type).toBe('datetime-local');
    expect(container.querySelector(`input[aria-label="${strings.addValueTo('Other')}"]`)).toBeNull();
    await typeInto(input, '2026-12-01T08:00');
    await click(button(strings.add));

    expect(last().values.m).toEqual({
        kind: 'options',
        value: [{ kind: 'added', value: { kind: 'dateTime', value: expect.stringMatching(/^2026-12-01T08:00:00\.000[+-]\d\d:\d\d$/) } }],
    });
});

test('a list that is not extensible has no Add value, and an empty one adds nothing', async () => {
    await render(form([field({ name: 'm', label: 'Department', kind: 'multiselect', options: levels })]));

    expect(container.querySelector('input[type="text"]')).toBeNull();
    expect(button(strings.add)).toBeUndefined();
});

test('info is a label and plain text with nothing to fill in; hidden fields have no control', async () => {
    await render(
        form([
            field({ name: 'i', label: 'Note', kind: 'info', value: text('Attributes marked with a lock are set by ILM.') }),
            field({ name: 'h', label: 'Secret', hidden: true, kind: null, value: text('x') }),
        ]),
    );

    expect(container.textContent).toContain('NoteAttributes marked with a lock are set by ILM.');
    expect(container.querySelector('input, textarea, select')).toBeNull();
    expect(container.textContent).not.toContain('Secret');
    expect(last().values).toEqual({});
});

test('a read-only field shows its value as plain text with a lock, and ignores the keyboard', async () => {
    await render(
        form([
            field({ name: 'o', label: 'Owner', required: true, readOnly: true, value: text('Alex Morgan') }),
            field({ name: 'k', label: 'Level', kind: 'select', readOnly: true, options: levels, value: { kind: 'option', value: 'k1' } }),
            field({ name: 's', label: 'Key', kind: 'secret', readOnly: true, value: text('x') }),
            field({ name: 'c', label: 'Script', kind: 'code', readOnly: true, value: { kind: 'code', value: 'exit 0' } }),
            field({
                name: 'm',
                label: 'Teams',
                kind: 'multiselect',
                readOnly: true,
                options: levels,
                value: { kind: 'options', value: [{ kind: 'option', value: 'k0' }] },
            }),
            field({ name: 'b', label: 'Notify', kind: 'switch', readOnly: true, value: { kind: 'bool', value: true } }),
        ]),
    );

    const owner = group('Owner');
    expect(owner.textContent).toContain('Alex Morgan');
    expect(owner.querySelector('[role="img"]')?.getAttribute('aria-label')).toBe(strings.attributeReadOnly);
    expect(group('Level').textContent).toContain('Medium');
    expect(group('Key').textContent).toContain('\u2022\u2022');
    expect(group('Script').querySelector('p')?.className).toContain('font-mono');
    expect(group('Teams').textContent).toContain('Low');
    expect(container.querySelector('input[type="text"], select, textarea')).toBeNull();
    const toggle = container.querySelector('[role="switch"]') as HTMLInputElement;
    expect(toggle.disabled).toBe(true);
});

test('groups have their titles, the ungrouped first under Custom attributes, and a group without fields to show is left out', async () => {
    await render({
        id: 'form-1',
        revision: 0,
        unsupported: [],
        web: null,
        groups: [
            { title: null, fields: [field({ name: 'a', label: 'A' })] },
            { title: 'Contacts', fields: [field({ name: 'b', label: 'B' })] },
            { title: 'Empty', fields: [field({ name: 'h', hidden: true, kind: null })] },
        ],
    });

    const sections = [...container.querySelectorAll('section')];
    expect(sections.map((section) => section.querySelector('h3')?.textContent)).toEqual([strings.customAttributes, 'Contacts', 'Empty']);
    expect(sections[0]?.getAttribute('aria-labelledby')).toBe(sections[0]?.querySelector('h3')?.id);
});

test('a required attribute the application cannot show says so and opens ILM, and the form cannot be sent', async () => {
    await render(form([field({ name: 'a', label: 'A' })], { unsupported: ['Cost center'] }));

    expect(container.textContent).toContain(strings.attributeUnsupported('Cost center'));
    expect(container.querySelector('section')?.querySelector('h3')?.textContent).toBe(strings.customAttributes);
    expect(last().ready).toBe(false);
    await click(button(strings.openInIlm));

    expect(opened).toEqual([{ target: 'addToIlm' }]);
    expect(container.querySelector('[role="alert"]')).toBeNull();
});

test('when only unsupported attributes are left the ungrouped part holds them, and a refusal to open says so', async () => {
    openRefused = true;
    await render({
        id: 'form-1',
        revision: 0,
        unsupported: ['Cost center'],
        web: null,
        groups: [{ title: 'Contacts', fields: [field({ name: 'b', label: 'B' })] }],
    });

    expect([...container.querySelectorAll('h3')].map((heading) => heading.textContent)).toEqual([strings.customAttributes, 'Contacts']);
    await click(button(strings.openInIlm));

    expect(container.querySelector('[role="alert"]')?.textContent).toBe(strings.openInIlmFailed);
});

test('the form is ready once the core has checked the values and found no problem', async () => {
    await render(form([field({ name: 'a', label: 'A', required: true })]));

    expect(checks).toHaveLength(1);
    expect(last().ready).toBe(true);
    expect(states[0]?.ready).toBe(false);
});

test('the values are checked once they rest, not at every key', async () => {
    await render(form([field({ name: 'a', label: 'A' })]));
    checks.length = 0;

    await typeInto(control('A'), 'a');
    await wait(checkDelay - 50);
    await typeInto(control('A'), 'ab');
    await wait(checkDelay - 50);
    expect(checks).toHaveLength(0);
    expect(last().ready).toBe(false);
    await wait(60);

    expect(checks).toEqual([{ a: text('ab') }]);
    expect(last().ready).toBe(true);
});

test('a problem shows once the person has left the field, with the words of the problem and tied to the control', async () => {
    problems = [{ name: 'i', problem: { kind: 'notInteger' } }];
    await render(form([field({ name: 'i', label: 'TestInt', kind: 'integer' })]));
    const input = control('TestInt');

    expect(container.textContent).not.toContain('Enter a whole number.');
    expect(last().ready).toBe(false);
    await leave(input);

    expect(describedBy(input)).toBe('Enter a whole number.');
    expect(input.getAttribute('aria-invalid')).toBe('true');
});

test('every problem shows once the person tried to send, and what ILM says about a rule wins', async () => {
    problems = [
        { name: 'p', problem: { kind: 'pattern', message: 'Use a company address.' } },
        { name: 'n', problem: { kind: 'below', min: 3, message: null } },
        { name: 'r', problem: { kind: 'required' } },
    ];
    await render(
        form([
            field({ name: 'p', label: 'Mail' }),
            field({ name: 'n', label: 'Count', kind: 'integer' }),
            field({ name: 'r', label: 'Level', kind: 'select', options: levels, required: true }),
        ]),
        { submitted: true },
    );

    expect(describedBy(control('Mail'))).toBe('Use a company address.');
    expect(describedBy(control('Count'))).toBe('Use 3 or more.');
    expect(describedBy(control('Level'))).toBe('Choose a value.');
});

test('the fields the core refused when the form was sent show their problem at once', async () => {
    problems = [{ name: 'a', problem: { kind: 'required' } }];
    await render(form([field({ name: 'a', label: 'A', required: true })]), {
        serverProblems: [{ name: 'a', problem: { kind: 'required' } }],
    });

    expect(describedBy(control('A'))).toBe('Enter a value.');
});

test('a problem on a field that is touched but fine shows nothing, and a failed check keeps the form from being sent', async () => {
    await render(form([field({ name: 'a', label: 'A' })]));
    await leave(control('A'));
    expect(container.querySelector('[id$="-problem"]')).toBeNull();

    await act(async () => clearMocks());
    mockIPC((command) => (command === 'check_attributes' ? Promise.reject('gone') : undefined));
    await typeInto(control('A'), 'x');
    await wait(checkDelay);

    expect(container.querySelector('[role="alert"]')?.textContent).toBe(strings.attributeCheckFailed);
    expect(last().ready).toBe(false);
});

/** A field that holds no control but whose callback adds the fields of a group, as the core lists it. */
const hidden = (name: string, callback: AttributeFieldView['callback']) => field({ name, label: name, hidden: true, kind: null, callback });
const watcher = (name: string, ...on: string[]) =>
    field({ name, label: name.toUpperCase(), kind: 'select', callback: { kind: 'onChange', value: on } });
const labels = () => [...container.querySelectorAll('label')].map((label) => label.textContent);
const optionTexts = (label: string) => [...control(label).options].map((option) => option.textContent);

/** Answers each run when the test says so, by field and sequence number. */
const holdAnswers = () => {
    const pending: Record<string, (result: AttributeCallbackResult) => void> = {};
    const failing: Record<string, () => void> = {};
    answer = ({ field: name, seq }) =>
        new Promise((resolve, reject) => {
            pending[`${name}${seq}`] = resolve;
            failing[`${name}${seq}`] = () => reject('failed');
        });
    return {
        finish: (name: string, seq: number, next: AttributeFormView, problem: string | null = null) =>
            act(async () => pending[`${name}${seq}`]?.(reply({ field: name, seq }, next, problem))),
        fail: (name: string, seq: number) => act(async () => failing[`${name}${seq}`]?.()),
    };
};

test('a field with a callback on open runs it once with the typed values and a sequence number, and the snapshot it brings is drawn', async () => {
    const callback = { kind: 'onOpen' } as const;
    const options = [
        { key: 'ka', label: 'Alpha' },
        { key: 'kb', label: 'Beta' },
    ];
    answer = (call) =>
        reply(
            call,
            form(
                [
                    field({
                        name: 'c',
                        label: 'Credential',
                        kind: 'select',
                        callback,
                        options,
                        value: { kind: 'option', value: 'ka' },
                        changedAt: 1,
                        valueSetAt: 1,
                    }),
                ],
                {
                    revision: 1,
                },
            ),
        );
    await render(form([field({ name: 'c', label: 'Credential', kind: 'select', callback })]));
    await wait(callbackDelay);

    expect(asked).toEqual([{ field: 'c', seq: 1, values: {} }]);
    expect(optionTexts('Credential')).toEqual([strings.none, 'Alpha', 'Beta']);
    expect(control('Credential').value).toBe('ka');
    expect(last().values).toEqual({ c: { kind: 'option', value: 'ka' } });
});

test('a callback that finds no value leaves the field without one', async () => {
    const callback = { kind: 'onOpen' } as const;
    answer = (call) =>
        reply(
            call,
            form([field({ name: 'c', label: 'Credential', kind: 'select', callback, changedAt: 1, valueSetAt: 1 })], { revision: 1 }),
        );
    await render(
        form([
            field({ name: 'c', label: 'Credential', kind: 'select', options: levels, value: { kind: 'option', value: 'k1' }, callback }),
        ]),
    );

    expect(last().values).toEqual({});
    expect(optionTexts('Credential')).toEqual([strings.none]);
});

test('a callback on change waits for the values to rest and runs with the new values', async () => {
    await render(form([field({ name: 'a', label: 'A' }), watcher('b', 'a')]));
    expect(asked).toEqual([]);

    await typeInto(control('A'), 'x');
    await wait(callbackDelay - 100);
    await typeInto(control('A'), 'xy');
    await wait(callbackDelay - 100);
    expect(asked).toEqual([]);
    await wait(100);

    expect(asked).toEqual([{ field: 'b', seq: 1, values: { a: text('xy') } }]);
});

test('a callback that depends on fields with values, hidden or read-only ones included, runs on open, and one whose dependencies are empty waits', async () => {
    await render(
        form([
            field({ name: 'a', label: 'A', value: text('given') }),
            field({ name: 'e', label: 'E' }),
            hidden('h', { kind: 'none' }),
            field({ name: 'r', label: 'R', readOnly: true, value: text('fixed') }),
            watcher('with', 'a'),
            watcher('without', 'a', 'e'),
            watcher('behind', 'h'),
            watcher('beside', 'r'),
            field({ name: 'none', label: 'None', kind: 'select', callback: { kind: 'onChange', value: [] } }),
        ]),
    );

    expect(asked.map((call) => call.field)).toEqual(['with', 'behind', 'beside', 'none']);
});

test('options and choices go to the core by key', async () => {
    await render(
        form([
            field({ name: 'x', label: 'X', kind: 'select', options: levels }),
            field({ name: 'm', label: 'M', kind: 'multiselect', options: levels }),
            watcher('w', 'x', 'm'),
        ]),
    );

    await choose(control('X'), 'k1');
    await click(group('M').querySelectorAll('input')[2]);
    await wait(callbackDelay);

    expect(asked).toEqual([
        {
            field: 'w',
            seq: 1,
            values: { x: { kind: 'option', value: 'k1' }, m: { kind: 'options', value: [{ kind: 'option', value: 'k2' }] } },
        },
    ]);
});

test('a snapshot older than the one drawn is ignored, whatever the order its answer arrives in', async () => {
    const run = holdAnswers();
    const at = (revision: number, ...labels: string[]) =>
        form(
            [
                field({ name: 'a', label: 'A' }),
                { ...watcher('b', 'a'), options: labels.map((label) => ({ key: label, label })), changedAt: revision },
            ],
            {
                revision,
            },
        );
    await render(form([field({ name: 'a', label: 'A' }), watcher('b', 'a')]));
    await typeInto(control('A'), 'x');
    await wait(callbackDelay);
    await typeInto(control('A'), 'xy');
    await wait(callbackDelay);
    expect(asked.map((call) => call.seq)).toEqual([1, 2]);

    await run.finish('b', 2, at(3, 'IT', 'Sales'));
    await run.finish('b', 1, at(2, 'Sales'));

    expect(optionTexts('B')).toEqual([strings.none, 'IT', 'Sales']);
});

test('what an older run committed is drawn although a newer run was dispatched before it arrived, and the newer failing changes nothing', async () => {
    const run = holdAnswers();
    await render(form([field({ name: 'a', label: 'A' }), watcher('b', 'a')]));
    await typeInto(control('A'), 'x');
    await wait(callbackDelay);
    await typeInto(control('A'), 'xy');
    await wait(callbackDelay);

    await run.finish(
        'b',
        1,
        form([field({ name: 'a', label: 'A' }), { ...watcher('b', 'a'), options: [{ key: 'ki', label: 'IT' }], changedAt: 2 }], {
            revision: 2,
        }),
    );
    await run.fail('b', 2);

    expect(optionTexts('B')).toEqual([strings.none, 'IT']);
    expect(describedBy(control('B'))).toBe(strings.callbackFailed);
});

test('a chosen option stays chosen when its key is still offered, wherever it moved, and goes when it is not offered', async () => {
    const choice = (...keys: string[]) => ({
        ...field({ name: 'x', label: 'X', kind: 'select', required: true }),
        options: keys.map((key) => ({ key, label: key.toUpperCase() })),
    });
    const trigger = hidden('g', { kind: 'onChange', value: ['t'] });
    const next = (revision: number, ...keys: string[]) =>
        form([field({ name: 't', label: 'T' }), { ...choice(...keys), changedAt: revision }, trigger], { revision });
    await render(form([field({ name: 't', label: 'T' }), choice('sales', 'it'), trigger]));
    await choose(control('X'), 'sales');
    answer = (call) => reply(call, next(1, 'it', 'sales'));

    await typeInto(control('T'), 'a');
    await wait(callbackDelay);

    expect(last().values.x).toEqual({ kind: 'option', value: 'sales' });
    expect(optionTexts('X')).toEqual(['IT', 'SALES']);
    expect(control('X').value).toBe('sales');

    answer = (call) => reply(call, next(2, 'ap'));
    await typeInto(control('T'), 'b');
    await wait(callbackDelay);

    expect(last().values.x).toBeUndefined();
    expect(optionTexts('X')).toEqual([strings.selectValue, 'AP']);
});

test('a field takes the value ILM set when its valueSetAt grew, and keeps what the person typed when it did not', async () => {
    const trigger = hidden('g', { kind: 'onChange', value: ['t'] });
    const next = (revision: number, m: Partial<AttributeFieldView>, n: Partial<AttributeFieldView>) =>
        form([field({ name: 't', label: 'T' }), field({ name: 'm', label: 'M', ...m }), field({ name: 'n', label: 'N', ...n }), trigger], {
            revision,
        });
    await render(form([field({ name: 't', label: 'T' }), field({ name: 'm', label: 'M' }), field({ name: 'n', label: 'N' }), trigger]));
    answer = (call) => reply(call, next(1, { value: text('from ILM'), changedAt: 1, valueSetAt: 1 }, {}));
    await typeInto(control('T'), 'a');
    await wait(callbackDelay);
    expect(last().values.m).toEqual(text('from ILM'));

    await typeInto(control('M'), 'mine');
    answer = (call) =>
        reply(call, next(2, { changedAt: 2, valueSetAt: 1, value: text('from ILM') }, { value: text('new'), changedAt: 2, valueSetAt: 2 }));
    await typeInto(control('T'), 'b');
    await wait(callbackDelay);

    expect(last().values).toEqual({ t: text('b'), m: text('mine'), n: text('new') });

    answer = (call) => reply(call, next(3, { value: null, changedAt: 3, valueSetAt: 3 }, { changedAt: 2, valueSetAt: 2 }));
    await typeInto(control('T'), 'c');
    await wait(callbackDelay);

    expect(last().values).toEqual({ t: text('c'), n: text('new') });
});

test('a snapshot that retires an offered key drops it from the typed value and keeps the keys still offered', async () => {
    const trigger = hidden('g', { kind: 'onChange', value: ['t'] });
    const keys = (...picked: string[]) => picked.map((key) => ({ key, label: key.toUpperCase() }));
    const pick = (revision: number, ...offered: string[]) =>
        form(
            [
                field({ name: 't', label: 'T' }),
                field({ name: 'm', label: 'M', kind: 'multiselect', options: keys(...offered), changedAt: revision }),
                trigger,
            ],
            { revision },
        );
    await render(pick(0, 'sales', 'it'));
    await click(group('M').querySelectorAll('input[type="checkbox"]')[1]);
    expect(last().values.m).toEqual({ kind: 'options', value: [{ kind: 'option', value: 'it' }] });

    answer = (call) => reply(call, pick(1, 'ap', 'it'));
    await typeInto(control('T'), 'a');
    await wait(callbackDelay);
    expect(last().values.m).toEqual({ kind: 'options', value: [{ kind: 'option', value: 'it' }] });

    answer = (call) => reply(call, pick(2, 'ap'));
    await typeInto(control('T'), 'b');
    await wait(callbackDelay);
    expect(last().values.m).toBeUndefined();
});

test('a read is void when a field the file field watches changes, though the file field itself did not move', async () => {
    const readers = slowReads();
    const fields = [
        field({ name: 'f', label: 'Template', kind: 'file', callback: { kind: 'onChange', value: ['t'] } }),
        field({ name: 't', label: 'Trigger' }),
    ];
    await render(form(fields));
    await selecting('a.csr');

    await typeInto(control('Trigger'), 'go');
    await act(async () => readers[0]?.finish('QQ=='));
    await wait(callbackDelay + checkDelay);

    expect(last().values.f).toBeUndefined();
    expect(last().ready).toBe(true);
    vi.unstubAllGlobals();
});

test('fields that are gone from the snapshot lose their typed values and the answers shown for them', async () => {
    const trigger = hidden('g', { kind: 'onChange', value: ['t'] });
    const extra = field({ name: 'x', label: 'X', changedAt: 1, valueSetAt: 1 });
    answer = (call) => reply(call, form([field({ name: 't', label: 'T' }), trigger, extra], { revision: 1 }));
    await render(form([field({ name: 't', label: 'T' }), trigger]));
    await typeInto(control('T'), 'a');
    await wait(callbackDelay);
    await typeInto(control('X'), 'typed');
    expect(last().values.x).toEqual(text('typed'));

    answer = (call) => reply(call, form([field({ name: 't', label: 'T' }), trigger], { revision: 2 }), 'ILM did not answer.');
    await typeInto(control('T'), 'b');
    await wait(callbackDelay);

    expect(last().values).toEqual({ t: text('b') });
    expect(labels()).toEqual(['T']);
});

test('a callback runs when a hidden field or a read-only list it watches changed, though the snapshot shows no content', async () => {
    const fields = (changedAt: number) => [
        field({ name: 'a', label: 'A' }),
        { ...hidden('h', { kind: 'onChange', value: ['a'] }), changedAt },
        { ...field({ name: 'r', label: 'R', kind: 'select', readOnly: true, callback: { kind: 'onChange', value: ['a'] } }), changedAt },
        watcher('byHidden', 'h'),
        watcher('byReadOnly', 'r'),
    ];
    answer = (call) => (call.field === 'h' || call.field === 'r' ? reply(call, form(fields(1), { revision: 1 })) : reply(call, shown));
    await render(form(fields(0)));
    asked.length = 0;

    await typeInto(control('A'), 'go');
    await wait(callbackDelay);
    await wait(callbackDelay);

    expect(asked.map((call) => call.field).sort()).toEqual(['byHidden', 'byReadOnly', 'h', 'r']);
});

test('a committed change of a hidden field still schedules its watchers when the run that carried it was superseded', async () => {
    const run = holdAnswers();
    const fields = (changedAt: number) => [
        field({ name: 'a', label: 'A' }),
        { ...hidden('h', { kind: 'onChange', value: ['a'] }), changedAt },
        watcher('c', 'h'),
    ];
    await render(form(fields(0)));
    asked.length = 0;
    await typeInto(control('A'), 'x');
    await wait(callbackDelay);
    await typeInto(control('A'), 'xy');
    await wait(callbackDelay);
    expect(asked.map((call) => `${call.field}${call.seq}`)).toEqual(['h1', 'h2']);

    await run.finish('h', 1, form(fields(1), { revision: 1 }));
    await wait(callbackDelay);

    expect(asked.map((call) => call.field)).toEqual(['h', 'h', 'c']);
});

test('a cleared answer keeps a newer run of its own field that was queued after it was asked', async () => {
    const run = holdAnswers();
    await render(form([field({ name: 'a', label: 'A' }), watcher('b', 'a')]));
    await typeInto(control('A'), 'x');
    await wait(callbackDelay);
    await typeInto(control('A'), 'xy');

    await run.finish(
        'b',
        1,
        form([field({ name: 'a', label: 'A' }), { ...watcher('b', 'a'), changedAt: 1, valueSetAt: 1 }], { revision: 1 }),
    );
    await wait(callbackDelay);

    expect(asked.map((call) => call.seq)).toEqual([1, 2]);
});

test('a field a group replaced runs its own callback again, and loses the run that was waiting for it', async () => {
    const x = (resetAt: number) => ({
        ...field({ name: 'x', label: 'X', kind: 'select', callback: { kind: 'onChange', value: ['b'] } }),
        changedAt: resetAt,
        resetAt,
    });
    const fields = (changedAt: number) => [
        field({ name: 'a', label: 'A' }),
        field({ name: 'b', label: 'B', value: text('given') }),
        hidden('g', { kind: 'onChange', value: ['a'] }),
        x(changedAt),
    ];
    answer = (call) => reply(call, call.field === 'g' ? form(fields(1), { revision: 1 }) : shown);
    await render(form(fields(0)));
    expect(asked.map((call) => call.field)).toEqual(['x']);
    asked.length = 0;

    await typeInto(control('A'), 'go');
    await wait(callbackDelay - 100);
    await typeInto(control('B'), 'edited');
    await wait(100);
    expect(asked.map((call) => call.field)).toEqual(['g', 'x']);
    await wait(callbackDelay * 2);

    expect(asked.map((call) => call.field)).toEqual(['g', 'x']);
});

test('a field whose own answer another reply carries is not run again, only one reset or installed is', async () => {
    const run = holdAnswers();
    const g = hidden('g', { kind: 'onOpen' });
    const y = hidden('y', { kind: 'onOpen' });
    await render(form([g, y]));
    expect(asked.map((call) => call.field)).toEqual(['g', 'y']);

    await run.finish('y', 1, form([{ ...g, changedAt: 1, valueSetAt: 1 }, y], { revision: 1 }), 'ILM did not answer.');

    expect(asked.map((call) => call.field)).toEqual(['g', 'y']);

    await run.finish('g', 1, form([{ ...g, changedAt: 2, resetAt: 2 }, y], { revision: 2 }));

    expect(asked.map((call) => call.field)).toEqual(['g', 'y', 'g']);
});

test('two fields whose callbacks watch each other stop calling once ILM repeats its answers', async () => {
    let revision = 0;
    const fields = () => [
        field({
            name: 'a',
            label: 'A',
            value: text('1'),
            callback: { kind: 'onChange', value: ['b'] },
            changedAt: 1,
            valueSetAt: revision,
        }),
        field({
            name: 'b',
            label: 'B',
            value: text('1'),
            callback: { kind: 'onChange', value: ['a'] },
            changedAt: 1,
            valueSetAt: revision,
        }),
    ];
    answer = (call) => {
        revision += 1;
        return reply(call, form(fields(), { revision }));
    };
    await render(
        form([
            field({ name: 'a', label: 'A', value: text('1'), callback: { kind: 'onChange', value: ['b'] } }),
            field({ name: 'b', label: 'B', value: text('1'), callback: { kind: 'onChange', value: ['a'] } }),
        ]),
    );
    await wait(callbackDelay * 3);
    const settled = asked.length;
    await wait(callbackDelay * 5);

    expect(asked).toHaveLength(settled);
    expect(settled).toBeLessThanOrEqual(4);
});

test('a callback ILM did not answer says so on its field, and the next run takes it away', async () => {
    answer = (call) => reply(call, shown, 'ILM did not answer.');
    await render(form([field({ name: 'a', label: 'A' }), watcher('b', 'a'), hidden('g', { kind: 'onOpen' })]));

    expect(container.querySelectorAll('[role="alert"]')).toHaveLength(1);
    expect(container.querySelector('[role="alert"]')?.textContent).toBe('ILM did not answer.');
    answer = (call) => reply(call, shown);
    await typeInto(control('A'), 'x');
    await wait(callbackDelay);

    expect(describedBy(control('B'))).toBe('');
    expect(container.querySelectorAll('[role="alert"]')).toHaveLength(1);
});

test('a command that fails says the same on the field', async () => {
    answer = () => Promise.reject('locked') as never;
    await render(form([field({ name: 'b', label: 'B', kind: 'select', callback: { kind: 'onOpen' } })]));

    expect(describedBy(control('B'))).toBe(strings.callbackFailed);
});

test('the answers of a form that is gone are dropped', async () => {
    const run = holdAnswers();
    await render(form([field({ name: 'b', label: 'B', kind: 'select', callback: { kind: 'onOpen' } })]));

    await act(async () => root.render(null));
    await run.finish('b', 1, shown, 'late');

    expect(container.textContent).toBe('');
});

test('while the form is busy nothing can be changed or opened', async () => {
    await render(form([field({ name: 'a', label: 'A' }), field({ name: 's', label: 'S', kind: 'secret' })], { unsupported: ['Cost'] }), {
        disabled: true,
    });

    expect(control('A').disabled).toBe(true);
    expect((button(strings.openInIlm) as HTMLButtonElement).disabled).toBe(true);
    expect((button(strings.showSecret) as HTMLButtonElement).disabled).toBe(true);
});

test('the fields a group callback adds follow it, however deep, run their own callbacks and go when the snapshot drops them', async () => {
    const a = field({ name: 'a', label: 'A' });
    const g = hidden('g', { kind: 'onChange', value: ['a'] });
    const k = hidden('k', { kind: 'onChange', value: ['a'] });
    const x = field({ name: 'x', label: 'Outer', changedAt: 1, valueSetAt: 1 });
    const y = field({ name: 'y', label: 'Inner', changedAt: 2, valueSetAt: 2 });
    answer = (call) =>
        call.field === 'g'
            ? reply(call, form([a, { ...g, changedAt: 1 }, x, { ...k, changedAt: 1 }], { revision: 1 }))
            : reply(call, form([a, { ...g, changedAt: 1 }, x, { ...k, changedAt: 1 }, y], { revision: 2 }));
    await render(form([a, g]));
    await typeInto(control('A'), 'go');
    await wait(callbackDelay);
    await wait(callbackDelay);

    expect(asked.map((call) => call.field)).toEqual(['g', 'k']);
    expect(labels()).toEqual(['A', 'Outer', 'Inner']);

    answer = (call) => reply(call, form([a, { ...g, changedAt: 3 }], { revision: 3 }));
    await typeInto(control('A'), 'again');
    await wait(callbackDelay);

    expect(labels()).toEqual(['A']);
});

test('the form is ready only once the core has checked the snapshot that is drawn', async () => {
    const trigger = hidden('g', { kind: 'onChange', value: ['t'] });
    await render(form([field({ name: 't', label: 'T' }), trigger]));
    expect(last().ready).toBe(true);
    answer = (call) => {
        coreRevision = 1;
        return reply(call, form([field({ name: 't', label: 'T' }), { ...trigger, changedAt: 1 }], { revision: 1 }));
    };
    checks.length = 0;

    await typeInto(control('T'), 'a');
    await wait(callbackDelay);
    expect(last().ready).toBe(false);
    await wait(checkDelay);

    expect(last().ready).toBe(true);
    expect(checks.length).toBeGreaterThan(0);
});

test('a check made against another revision than the snapshot drawn does not make the form ready', async () => {
    mockIPC((command) => (command === 'check_attributes' ? { revision: 7, problems: [] } : undefined));
    await render(form([field({ name: 'a', label: 'A' })]));
    await wait(checkDelay);

    expect(last().ready).toBe(false);
});

test('the form is not ready while a callback is scheduled or running, and is once it has answered', async () => {
    const run = holdAnswers();
    await render(form([field({ name: 'a', label: 'A' }), watcher('b', 'a')]));
    expect(last().ready).toBe(true);

    await typeInto(control('A'), 'x');
    await wait(checkDelay + 50);
    expect(asked).toEqual([]);
    expect(last().ready).toBe(false);

    await wait(callbackDelay);
    expect(asked).toHaveLength(1);
    expect(last().ready).toBe(false);

    await run.finish('b', 1, shown);
    await wait(checkDelay + 50);
    expect(last().ready).toBe(true);
});

test('a callback that failed no longer keeps the form from being ready', async () => {
    const run = holdAnswers();
    await render(form([field({ name: 'a', label: 'A' }), watcher('b', 'a')]));

    await typeInto(control('A'), 'x');
    await wait(callbackDelay);
    await run.fail('b', 1);
    await wait(checkDelay + 50);

    expect(last().ready).toBe(true);
});

test('a scheduled callback that is run by a newer edit keeps the form not ready until the last run answers', async () => {
    const run = holdAnswers();
    await render(form([field({ name: 'a', label: 'A' }), watcher('b', 'a')]));

    await typeInto(control('A'), 'x');
    await wait(callbackDelay);
    await typeInto(control('A'), 'xy');
    await run.finish('b', 1, shown);
    await wait(checkDelay + 50);
    expect(last().ready).toBe(false);

    await wait(callbackDelay);
    await run.finish('b', 2, shown);
    await wait(checkDelay + 50);
    expect(last().ready).toBe(true);
});

test('a field the callbacks add to unchanged values is checked before the form is ready', async () => {
    const trigger = hidden('g', { kind: 'onChange', value: ['t'] });
    await render(form([field({ name: 't', label: 'T' }), trigger]));
    expect(last().ready).toBe(true);
    answer = (call) => {
        coreRevision = 1;
        problems = [{ name: 'x', problem: { kind: 'required' } }];
        return reply(
            call,
            form(
                [field({ name: 't', label: 'T' }), trigger, field({ name: 'x', label: 'X', required: true, changedAt: 1, valueSetAt: 1 })],
                {
                    revision: 1,
                },
            ),
        );
    };

    await typeInto(control('T'), 'a');
    await wait(callbackDelay);
    await wait(checkDelay);

    expect(last().ready).toBe(false);
    await leave(control('X'));
    expect(describedBy(control('X'))).toBe('Enter a value.');
});

test('every blocker of the newest snapshot keeps the form from being sent, whichever run carried it, and an older snapshot brings none back', async () => {
    const run = holdAnswers();
    const trigger = hidden('g', { kind: 'onChange', value: ['t'] });
    const at = (revision: number, ...unsupported: string[]) =>
        form([field({ name: 't', label: 'T' }), { ...trigger, changedAt: revision }], { revision, unsupported });
    await render(form([field({ name: 't', label: 'T' }), trigger]));
    await typeInto(control('T'), 'a');
    await wait(callbackDelay);
    await typeInto(control('T'), 'ab');
    await wait(callbackDelay);

    await run.finish('g', 1, at(2, 'Cost center'));
    await run.fail('g', 2);

    expect(container.textContent).toContain(strings.attributeUnsupported('Cost center'));
    expect(last().blocked).toBe(true);
    await typeInto(control('T'), 'abc');
    await wait(callbackDelay);
    await run.finish('g', 3, at(3));
    expect(container.textContent).not.toContain(strings.attributeUnsupported('Cost center'));
    await wait(checkDelay);
    expect(last().blocked).toBe(false);
    await run.finish('g', 1, at(2, 'Cost center'));
    expect(last().blocked).toBe(false);
});

test('a problem that appears is announced, and a list of checkboxes and the file button are tied to it', async () => {
    problems = [
        { name: 'm', problem: { kind: 'required' } },
        { name: 'f', problem: { kind: 'required' } },
        { name: 't', problem: { kind: 'required' } },
    ];
    await render(
        form([
            field({ name: 'm', label: 'Department', kind: 'multiselect', options: levels, required: true }),
            field({ name: 'f', label: 'Template', kind: 'file', required: true }),
            field({ name: 't', label: 'Title', required: true }),
        ]),
        { submitted: true },
    );

    const alerts = [...container.querySelectorAll('[role="alert"]')];
    expect(alerts.map((item) => item.textContent)).toEqual([
        strings.attributeProblem({ kind: 'required' }, 'multiselect'),
        strings.attributeProblem({ kind: 'required' }, 'file'),
        strings.attributeProblem({ kind: 'required' }, 'textline'),
    ]);
    expect(container.querySelectorAll('[aria-live]')).toHaveLength(0);
    for (const box of group('Department').querySelectorAll('input[type="checkbox"]')) {
        expect(describedBy(box)).toBe(alerts[0]?.textContent);
    }
    expect(describedBy(button(strings.chooseFile) as Element)).toBe(alerts[1]?.textContent);
});

/** A form whose hidden field answers with a snapshot that moves the file field `f`. */
const movingFile = async (moved: Partial<AttributeFieldView> = { changedAt: 1, valueSetAt: 1 }) => {
    const readers = slowReads();
    const fields = (extra: Partial<AttributeFieldView> = {}) => [
        field({ name: 'f', label: 'Template', kind: 'file', ...extra }),
        field({ name: 't', label: 'Trigger' }),
        hidden('g', { kind: 'onChange', value: ['t'] }),
    ];
    await render(form(fields()));
    answer = (call) => {
        coreRevision = 1;
        return reply(call, form(fields(moved), { revision: 1 }));
    };
    return {
        readers,
        move: async () => {
            await typeInto(control('Trigger'), 'go');
            await wait(callbackDelay);
        },
        movesWhile: (during: () => void) =>
            act(async () => {
                await typeInto(control('Trigger'), 'go');
                await vi.advanceTimersByTimeAsync(callbackDelay);
                during();
            }),
    };
};

test('a read whose field the form changed meanwhile is dropped and does not keep the form busy', async () => {
    const { readers, move } = await movingFile();
    await selecting('a.csr');

    await move();
    await act(async () => readers[0]?.finish('QQ=='));
    await wait(checkDelay);

    expect(last().values.f).toBeUndefined();
    expect(last().ready).toBe(true);
    vi.unstubAllGlobals();
});

test('a read that finishes in the same tick as the snapshot that replaced its field does not write into the fresh field', async () => {
    const { readers, movesWhile } = await movingFile();
    await selecting('a.csr');

    await movesWhile(() => readers[0]?.finish('QQ=='));
    await wait(checkDelay);

    expect(last().values.f).toBeUndefined();
    expect(last().ready).toBe(true);
    vi.unstubAllGlobals();
});

test('a file that cannot be read says so and keeps the form from being sent until another is chosen', async () => {
    const readers = slowReads();
    await render(form([field({ name: 'f', label: 'Template', kind: 'file' })]));

    await selecting('a.csr');
    await act(async () => readers[0]?.fail());
    await wait(checkDelay);

    expect(last().values.f).toBeUndefined();
    expect(last().ready).toBe(false);
    const chooser = button(strings.chooseFile) as HTMLButtonElement;
    expect(describedBy(chooser)).toBe(strings.fileUnreadable);
    expect(chooser.parentElement?.getAttribute('aria-invalid')).toBe('true');

    await selecting('b.csr');
    await act(async () => readers[1]?.finish('Qg=='));
    await wait(checkDelay);

    expect(last().ready).toBe(true);
    expect(describedBy(chooser)).toBe('');
    vi.unstubAllGlobals();
});

test('a file the reader does not give as text is taken as unreadable', async () => {
    const readers = slowReads();
    await render(form([field({ name: 'f', label: 'Template', kind: 'file' })]));

    await selecting('a.csr');
    const result = new ArrayBuffer(1);
    vi.stubGlobal(
        'FileReader',
        class {
            result = result;
            onload: (() => void) | null = null;
            onerror: (() => void) | null = null;
            readAsDataURL() {
                queueMicrotask(() => this.onload?.());
            }
        },
    );
    await selecting('b.csr');
    await wait(checkDelay);

    expect(readers).toHaveLength(1);
    expect(last().values.f).toBeUndefined();
    expect(describedBy(button(strings.chooseFile) as HTMLButtonElement)).toBe(strings.fileUnreadable);
    vi.unstubAllGlobals();
});

/** A file field that watches the field `a`; the callbacks settle once `a` has been changed. */
const watchingFile = async () => {
    await render(
        form([
            field({ name: 'a', label: 'Source' }),
            field({ name: 'f', label: 'Template', kind: 'file', callback: { kind: 'onChange', value: ['a'] } }),
        ]),
    );
    return {
        changeSource: async (value: string) => {
            await typeInto(control('Source'), value);
            await wait(callbackDelay);
        },
        selectLarge: () => {
            const input = container.querySelector('input[type="file"]') as HTMLInputElement;
            const big = new File(['x'.repeat(1024 * 1024 + 1)], 'big.bin', { type: 'text/plain' });
            Object.defineProperty(input, 'files', { configurable: true, value: [big] });
            return act(async () => {
                input.dispatchEvent(new Event('change', { bubbles: true }));
            });
        },
    };
};

const tooLarge = () => strings.attributeProblem({ kind: 'fileTooLarge', max: 1048576 }, 'file');

test.each([
    ['cannot be read', strings.fileUnreadable],
    ['is too large', tooLarge()],
])('a file that %s is reported on a field that watches another that has changed', async (kind, words) => {
    const readers = slowReads();
    const { changeSource, selectLarge } = await watchingFile();
    await changeSource('x');

    if (kind === 'cannot be read') {
        await selecting('a.csr');
        await act(async () => readers[0]?.fail());
    } else {
        await selectLarge();
    }

    expect(describedBy(button(strings.chooseFile) as Element)).toBe(words);
    expect(button(strings.removeFile('Template'))).toBeDefined();
    vi.unstubAllGlobals();
});

test.each([
    ['cannot be read', strings.fileUnreadable],
    ['is too large', tooLarge()],
])('the report of a file that %s goes when a field the file field watches changes', async (kind, words) => {
    const readers = slowReads();
    const { changeSource, selectLarge } = await watchingFile();

    if (kind === 'cannot be read') {
        await selecting('a.csr');
        await act(async () => readers[0]?.fail());
    } else {
        await selectLarge();
    }
    expect(describedBy(button(strings.chooseFile) as Element)).toBe(words);

    await changeSource('x');

    expect(describedBy(button(strings.chooseFile) as Element)).toBe('');
    expect(button(strings.removeFile('Template'))).toBeUndefined();
    vi.unstubAllGlobals();
});

const heads: [string, AttributeFieldView['callback']][] = [
    ['a chain of watchers', { kind: 'none' }],
    ['a cycle of watchers', { kind: 'onChange', value: ['b'] }],
];

test.each(heads)('a file read behind %s is dropped when the first one changes, and the form is not busy', async (_kind, head) => {
    const readers = slowReads();
    await render(
        form([
            field({ name: 'a', label: 'Source', callback: head }),
            field({ name: 'b', label: 'Middle', callback: { kind: 'onChange', value: ['a'] } }),
            field({ name: 'f', label: 'Template', kind: 'file', callback: { kind: 'onChange', value: ['b'] } }),
        ]),
    );

    await selecting('a.csr');
    await typeInto(control('Source'), 'x');
    await act(async () => readers[0]?.finish('QQ=='));
    await wait(callbackDelay + checkDelay);

    expect(last().values.f).toBeUndefined();
    expect(last().ready).toBe(true);
    vi.unstubAllGlobals();
});

test.each([
    ['cannot be read', strings.fileUnreadable],
    ['is too large', tooLarge()],
])('a replacement file that %s is reported when the file field and a field it watches watch each other', async (kind, words) => {
    const readers = slowReads();
    await render(
        form([
            field({ name: 'b', label: 'Middle', callback: { kind: 'onChange', value: ['f'] } }),
            field({ name: 'f', label: 'Template', kind: 'file', callback: { kind: 'onChange', value: ['b'] } }),
        ]),
    );
    await selecting('a.csr');
    await act(async () => readers[0]?.finish('QQ=='));
    await wait(checkDelay);
    expect(last().values.f).toBeDefined();

    if (kind === 'cannot be read') {
        await selecting('b.csr');
        await act(async () => readers[1]?.fail());
    } else {
        const input = container.querySelector('input[type="file"]') as HTMLInputElement;
        const big = new File(['x'.repeat(1024 * 1024 + 1)], 'big.bin', { type: 'text/plain' });
        Object.defineProperty(input, 'files', { configurable: true, value: [big] });
        await act(async () => {
            input.dispatchEvent(new Event('change', { bubbles: true }));
        });
    }
    await wait(checkDelay);

    expect(describedBy(button(strings.chooseFile) as Element)).toBe(words);
    expect(button(strings.removeFile('Template'))).toBeDefined();
    expect(last().ready).toBe(false);
    vi.unstubAllGlobals();
});

test('Remove clears a chosen file, shows the Required problem on a required field and returns focus to the chooser', async () => {
    await render(form([field({ name: 'f', label: 'Template', kind: 'file', required: true })]), { submitted: true });
    expect(button(strings.removeFile('Template'))).toBeUndefined();
    await choosing('client.csr', 10);
    expect(last().values.f).toBeDefined();
    problems = [{ name: 'f', problem: { kind: 'required' } }];

    const remove = button(strings.removeFile('Template')) as HTMLButtonElement;
    await click(remove);
    await act(async () => new Promise((resolve) => setTimeout(resolve, checkDelay + 50)));

    expect(last().values.f).toBeUndefined();
    expect(last().ready).toBe(false);
    expect(container.textContent).toContain(strings.noFileChosen);
    expect(button(strings.removeFile('Template'))).toBeUndefined();
    expect(document.activeElement).toBe(button(strings.chooseFile));
    expect(describedBy(button(strings.chooseFile) as Element)).toBe(strings.attributeProblem({ kind: 'required' }, 'file'));
});

test('a file that is too large keeps an optional form from being sent until Remove', async () => {
    await render(form([field({ name: 'f', label: 'Template', kind: 'file' })]));
    await choosing('big.bin', 1024 * 1024 + 1);
    await act(async () => new Promise((resolve) => setTimeout(resolve, checkDelay + 50)));

    expect(describedBy(button(strings.chooseFile) as Element)).toBe(tooLarge());
    expect(last().ready).toBe(false);

    await click(button(strings.removeFile('Template')));
    await act(async () => new Promise((resolve) => setTimeout(resolve, checkDelay + 50)));

    expect(describedBy(button(strings.chooseFile) as Element)).toBe('');
    expect(last().ready).toBe(true);
});

test('Remove clears the size error', async () => {
    await render(form([field({ name: 'f', label: 'Template', kind: 'file' })]));
    await choosing('big.bin', 1024 * 1024 + 1);
    const chooser = button(strings.chooseFile) as HTMLButtonElement;
    expect(describedBy(chooser)).toBe(strings.attributeProblem({ kind: 'fileTooLarge', max: 1048576 }, 'file'));

    await click(button(strings.removeFile('Template')));

    expect(describedBy(chooser)).toBe('');
    expect(button(strings.removeFile('Template'))).toBeUndefined();
});

test('Remove after a failed read makes an optional form ready, and is reachable by the keyboard', async () => {
    const readers = slowReads();
    await render(form([field({ name: 'f', label: 'Template', kind: 'file' })]));
    await selecting('a.csr');
    await act(async () => readers[0]?.fail());
    await wait(checkDelay);
    expect(last().ready).toBe(false);

    const remove = button(strings.removeFile('Template')) as HTMLButtonElement;
    expect(remove.tabIndex).toBe(0);
    expect(remove.disabled).toBe(false);
    await click(remove);
    await wait(checkDelay);

    expect(last().ready).toBe(true);
    expect(describedBy(button(strings.chooseFile) as Element)).toBe('');
    expect(document.activeElement).toBe(button(strings.chooseFile));
    vi.unstubAllGlobals();
});

test('no Remove is offered while the form is disabled', async () => {
    const view = form([field({ name: 'f', label: 'Template', kind: 'file' })]);
    await render(view);
    await choosing('client.csr', 10);
    expect(button(strings.removeFile('Template'))).toBeDefined();

    vi.useFakeTimers();
    await render(view, { disabled: true });
    expect(button(strings.removeFile('Template'))).toBeUndefined();

    await render(view, { disabled: false });
    expect(button(strings.removeFile('Template'))).toBeDefined();
});

test('the failure of a read is void once the form changes the field', async () => {
    const { readers, move } = await movingFile();
    await selecting('a.csr');
    await act(async () => readers[0]?.fail());
    expect(describedBy(button(strings.chooseFile) as Element)).toBe(strings.fileUnreadable);

    await move();
    await wait(checkDelay);

    expect(describedBy(button(strings.chooseFile) as Element)).toBe('');
    expect(last().ready).toBe(true);
    vi.unstubAllGlobals();
});

test('a read is void when only the value ILM set moved the field', async () => {
    const { readers, move } = await movingFile({ valueSetAt: 1 });
    await selecting('a.csr');

    await move();
    await act(async () => readers[0]?.finish('QQ=='));
    await wait(checkDelay);

    expect(last().values.f).toBeUndefined();
    expect(last().ready).toBe(true);
    vi.unstubAllGlobals();
});

test('the failure of a read is void once only the value ILM set moved the field', async () => {
    const { readers, move } = await movingFile({ valueSetAt: 1 });
    await selecting('a.csr');
    await act(async () => readers[0]?.fail());

    await move();
    await wait(checkDelay);

    expect(describedBy(button(strings.chooseFile) as Element)).toBe('');
    vi.unstubAllGlobals();
});

test('adopting a value that changes what the person typed wakes the watchers, and an identical one does not', async () => {
    const trigger = hidden('g', { kind: 'onChange', value: ['t'] });
    const at = (revision: number, value: string) =>
        form(
            [
                field({ name: 'a', label: 'A', value: text('x'), valueSetAt: revision }),
                field({ name: 't', label: 'T' }),
                trigger,
                watcher('c', 'a'),
            ],
            { revision },
        );
    await render(form([field({ name: 'a', label: 'A', value: text('x') }), field({ name: 't', label: 'T' }), trigger, watcher('c', 'a')]));
    await typeInto(control('A'), 'y');
    await wait(callbackDelay);
    asked.length = 0;

    answer = (call) => reply(call, at(1, 'x'));
    await typeInto(control('T'), 'go');
    await wait(callbackDelay);
    await wait(callbackDelay);
    expect(last().values.a).toEqual(text('x'));
    expect(asked.map((call) => call.field)).toEqual(['g', 'c']);

    asked.length = 0;
    answer = (call) => reply(call, at(2, 'x'));
    await typeInto(control('T'), 'again');
    await wait(callbackDelay);
    await wait(callbackDelay);
    expect(asked.map((call) => call.field)).toEqual(['g']);
});

test('the size error of a refused file does not outlive a replacement of the field, and the control stays', async () => {
    const { move } = await movingFile();
    await choosing('big.bin', 1024 * 1024 + 1);
    vi.useFakeTimers();
    const chooser = button(strings.chooseFile) as HTMLButtonElement;
    expect(chooser.parentElement?.getAttribute('aria-invalid')).toBe('true');

    await move();

    expect(button(strings.chooseFile)).toBe(chooser);
    expect(chooser.parentElement?.getAttribute('aria-invalid')).toBeNull();
    expect(describedBy(chooser)).toBe('');
});

test('a field a group replaces under the same name keeps the keyboard focus', async () => {
    const trigger = hidden('g', { kind: 'onChange', value: ['a'] });
    const x = (changedAt: number) => field({ name: 'x', label: 'X', changedAt, valueSetAt: changedAt });
    answer = (call) => reply(call, form([field({ name: 'a', label: 'A' }), trigger, x(call.seq)], { revision: call.seq }));
    await render(form([field({ name: 'a', label: 'A' }), trigger]));
    await typeInto(control('A'), 'one');
    await wait(callbackDelay);
    control('X').focus();
    expect(document.activeElement).toBe(control('X'));
    await typeInto(control('A'), 'two');
    await wait(callbackDelay);

    expect(document.activeElement).toBe(control('X'));
});
