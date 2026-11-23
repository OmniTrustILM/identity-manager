import { type ReactElement, useEffect, useId, useRef, useState } from 'react';
import {
    type AttributeFieldKind,
    type AttributeValue,
    type AttributeFieldProblem,
    type AttributeFieldView,
    type AttributeFormView,
    attributeCallback,
    checkAttributes,
    type FormValues,
    type IlmTarget,
} from '../../bridge';
import type { AttributeProblem } from '../../bridge/generated/AttributeProblem';
import { strings } from '../../strings';
import { SwitchField, InfoField, MultiSelectField, SelectField } from './ChoiceFields';
import { CodeField, JsonField } from './CodeFields';
import type { FieldProps } from './Field';
import { FileField } from './FileField';
import { DateField, DateTimeField, FloatField, IntegerField, SecretField, TextAreaField, TextLineField, TimeField } from './TextFields';
import { UnsupportedRow } from './UnsupportedRow';
import { givenValue, initialValues, isEmpty, movedAt, withoutGoneOptions, withValue } from './values';

/** How long the values rest before they are checked. */
export const checkDelay = 300;
/** How long the values a callback depends on rest before it runs, as in ILM's own web interface. */
export const callbackDelay = 600;

/** What the person has typed, whether the form is fit to be sent, and whether it needs ILM's web interface. */
export interface AttributeState {
    values: FormValues;
    ready: boolean;
    blocked: boolean;
}

const controls: Record<AttributeFieldKind, (props: FieldProps) => ReactElement> = {
    textline: TextLineField,
    textarea: TextAreaField,
    secret: SecretField,
    integer: IntegerField,
    float: FloatField,
    switch: SwitchField,
    date: DateField,
    time: TimeField,
    datetime: DateTimeField,
    file: FileField,
    code: CodeField,
    json: JsonField,
    select: SelectField,
    multiselect: MultiSelectField,
    info: InfoField,
};

/** The values a check was made for, the revision of the form it saw, and what it found (null: it could not be made). */
type Checked = { values: FormValues; revision: number; problems: AttributeFieldProblem[] | null };

const noProblems: AttributeFieldProblem[] = [];

const fieldsOf = (form: AttributeFormView): AttributeFieldView[] => form.groups.flatMap((group) => group.fields);

/** The groups as shown: the part without a title holds the rows of what cannot be shown. */
function sectionsOf(form: AttributeFormView) {
    const sections = form.groups;
    return form.unsupported.length > 0 && sections[0]?.title !== null ? [{ title: null, fields: [] }, ...sections] : sections;
}

/**
 * The form of the custom attributes ILM asks for. The core owns the form's structure and what ILM has set in it; this
 * draws the newest snapshot it has seen, holds what the person typed, runs the callbacks the snapshot asks for and tells
 * `onChange` the values and whether they may be sent.
 */
export function AttributeForm({
    form,
    target,
    disabled = false,
    submitted = false,
    serverProblems = noProblems,
    onChange,
}: Readonly<{
    form: AttributeFormView;
    target: IlmTarget;
    disabled?: boolean;
    /** The person tried to send: every problem shows. */
    submitted?: boolean;
    /** The fields the core refused when the form was sent. */
    serverProblems?: AttributeFieldProblem[];
    onChange: (state: AttributeState) => void;
}>) {
    const [snapshot, setSnapshot] = useState(form);
    const [values, setValues] = useState(() => initialValues(fieldsOf(form)));
    const [touched, setTouched] = useState<ReadonlySet<string>>(new Set());
    const [checked, setChecked] = useState<Checked | null>(null);
    const [answers, setAnswers] = useState<Record<string, string>>({});
    const [busy, setBusy] = useState<ReadonlySet<string>>(new Set());
    const [refusal, setRefusal] = useState<{ problems: AttributeFieldProblem[]; values: FormValues } | null>(null);
    const headings = useId();

    /** The newest snapshot and the typed values, current at once rather than at the next render. */
    const latest = useRef({ snapshot, values });
    const alive = useRef(false);
    /** The runs of each field so far; the core drops the answer of one that a newer run has replaced. */
    const seqs = useRef<Record<string, number>>({});
    /** The `valueSetAt` of each field that the typed values have taken. */
    const adopted = useRef<Record<string, number>>({});
    const timers = useRef(new Map<string, ReturnType<typeof setTimeout>>());
    const checkedOnce = useRef(false);

    const fields = () => fieldsOf(latest.current.snapshot);
    /** How often a field's pending file read was voided by a change of a field its callback watches. */
    const voided = useRef<Record<string, number>>({});
    /** Where a field stands: it grows when the field moves or a field it watches changes, so a file read begun before is dropped. */
    const changedAt = (name: string) => {
        const found = fields().find((field) => field.name === name);
        return found ? movedAt(found) + (voided.current[name] ?? 0) : 0;
    };
    /** Whether a field a callback depends on has a value; the core holds the content of a hidden or read-only one. */
    const hasValue = (name: string) => {
        const field = fields().find((candidate) => candidate.name === name);
        return field?.hidden === true || field?.readOnly === true || !isEmpty(latest.current.values[name]);
    };
    const due = ({ callback }: AttributeFieldView) =>
        callback.kind === 'onOpen' || (callback.kind === 'onChange' && callback.value.every((dependency) => hasValue(dependency)));
    const watchers = (name: string) => fields().filter(({ callback }) => callback.kind === 'onChange' && callback.value.includes(name));
    /**
     * The fields that watch these, and those that watch them in turn, however deep; a change of one may clear them all.
     * The fields named are left out, even when a cycle leads back to them.
     */
    const downstream = (names: Iterable<string>) => {
        const start = new Set(names);
        const found = new Set<string>(start);
        const todo = [...start];
        for (let name = todo.pop(); name !== undefined; name = todo.pop()) {
            for (const watcher of watchers(name)) {
                if (!found.has(watcher.name)) {
                    found.add(watcher.name);
                    todo.push(watcher.name);
                }
            }
        }
        return [...found].filter((name) => !start.has(name));
    };

    const unschedule = (name: string) => {
        clearTimeout(timers.current.get(name));
        timers.current.delete(name);
    };

    const schedule = (name: string) => {
        unschedule(name);
        timers.current.set(
            name,
            setTimeout(() => {
                timers.current.delete(name);
                run(name);
            }, callbackDelay),
        );
    };

    /** Voids the file reads pending for `names`: their results are dropped, so the form need not wait for them. */
    const voidReads = (names: readonly string[]) => {
        for (const name of names) {
            voided.current[name] = (voided.current[name] ?? 0) + 1;
        }
        setBusy((current) =>
            [...current].some((name) => names.includes(name)) ? new Set([...current].filter((name) => !names.includes(name))) : current,
        );
    };

    const run = (name: string) => {
        unschedule(name);
        const seq = (seqs.current[name] ?? 0) + 1;
        seqs.current[name] = seq;
        setAnswers((current) => {
            const { [name]: _, ...rest } = current;
            return name in current ? rest : current;
        });
        attributeCallback(form.id, name, latest.current.values, seq).then(
            (result) => {
                if (!alive.current) {
                    return;
                }
                take(result.form);
                if (seqs.current[result.field] === result.seq) {
                    setAnswers((current) => {
                        const { [result.field]: _, ...rest } = current;
                        return result.problem === null
                            ? result.field in current
                                ? rest
                                : current
                            : { ...rest, [result.field]: result.problem };
                    });
                }
            },
            () => {
                if (alive.current && seqs.current[name] === seq) {
                    setAnswers((current) => ({ ...current, [name]: strings.callbackFailed }));
                }
            },
        );
    };

    /**
     * Takes a snapshot of the form if it is newer than the one drawn: fields take the value ILM set since, and the
     * callbacks of reset fields and of fields watching a changed one are scheduled.
     */
    const take = (next: AttributeFormView) => {
        const before = latest.current.snapshot;
        if (next.revision <= before.revision) {
            return;
        }
        const known = new Map(fieldsOf(before).map((field) => [field.name, field]));
        const present = new Set(fieldsOf(next).map((field) => field.name));
        let typed = latest.current.values;
        for (const name of Object.keys(typed)) {
            if (!present.has(name)) {
                typed = withValue(typed, name, null);
            }
        }
        const moved: AttributeFieldView[] = [];
        const settling: AttributeFieldView[] = [];
        const reset: AttributeFieldView[] = [];
        for (const field of fieldsOf(next)) {
            if (field.valueSetAt > (adopted.current[field.name] ?? 0)) {
                adopted.current[field.name] = field.valueSetAt;
                const taken = withValue(typed, field.name, givenValue(field));
                if (taken !== typed) {
                    // The typed value changed under the field's dependants, though ILM's own stamp may not have moved.
                    moved.push(field);
                }
                typed = taken;
            }
            typed = withoutGoneOptions(typed, field);
            const before = known.get(field.name);
            if (field.changedAt > (before?.changedAt ?? -1)) {
                moved.push(field);
            }
            if (before && movedAt(field) > movedAt(before)) {
                settling.push(field);
            }
            if (field.resetAt > (known.get(field.name)?.resetAt ?? -1)) {
                reset.push(field);
            }
        }
        const gone = [...known.keys()].filter((name) => !present.has(name));
        for (const name of gone) {
            unschedule(name);
        }
        latest.current = { snapshot: next, values: typed };
        setSnapshot(next);
        setValues(typed);
        // A file being read for a field that has moved on is void: its result is dropped, so the form need not wait for it.
        // So is one of a field that watches a field that moved, however indirectly.
        const changed = new Set(moved.concat(settling).map((field) => field.name));
        voidReads([...gone, ...changed, ...downstream(changed)]);
        setAnswers((current) =>
            gone.some((name) => name in current)
                ? Object.fromEntries(Object.entries(current).filter(([name]) => present.has(name)))
                : current,
        );
        const now = new Set(reset.filter(due).map((field) => field.name));
        const later = new Set(moved.flatMap((field) => watchers(field.name).map((watcher) => watcher.name)));
        for (const name of now) {
            run(name);
        }
        for (const name of later) {
            if (!now.has(name)) {
                schedule(name);
            }
        }
    };

    /** The person changed a value: the callbacks that watch it follow once it rests. */
    const edit = (name: string, value: AttributeValue | undefined) => {
        const next = withValue(latest.current.values, name, value);
        if (next === latest.current.values) {
            return;
        }
        latest.current = { ...latest.current, values: next };
        setValues(next);
        voidReads(downstream([name]));
        for (const watcher of watchers(name)) {
            schedule(watcher.name);
        }
    };

    const atOpen = useRef(() => {});
    atOpen.current = () => {
        for (const field of fields()) {
            if (due(field)) {
                run(field.name);
            }
        }
    };
    useEffect(() => {
        alive.current = true;
        atOpen.current();
        const pending = timers.current;
        return () => {
            alive.current = false;
            for (const timer of pending.values()) {
                clearTimeout(timer);
            }
            pending.clear();
        };
    }, []);

    const revision = snapshot.revision;
    useEffect(() => {
        let current = true;
        const timer = setTimeout(
            () => {
                checkedOnce.current = true;
                checkAttributes(form.id, values).then(
                    (check) => current && check.revision === revision && setChecked({ values, revision, problems: check.problems }),
                    () => current && setChecked({ values, revision, problems: null }),
                );
            },
            checkedOnce.current ? checkDelay : 0,
        );
        return () => {
            current = false;
            clearTimeout(timer);
        };
    }, [form.id, values, revision]);

    const blocked = snapshot.unsupported.length > 0;
    const ready =
        checked !== null &&
        checked.values === values &&
        checked.revision === revision &&
        checked.problems?.length === 0 &&
        !blocked &&
        busy.size === 0;
    useEffect(() => {
        onChange({ values, ready, blocked });
    }, [onChange, values, ready, blocked]);

    useEffect(() => {
        if (serverProblems.length > 0) {
            setTouched((current) => new Set([...current, ...serverProblems.map((problem) => problem.name)]));
            setRefusal({ problems: serverProblems, values: latest.current.values });
        }
    }, [serverProblems]);

    const problems = new Map<string, AttributeProblem>();
    for (const { name, problem } of refusal?.problems ?? []) {
        if (values[name] === refusal?.values[name]) {
            problems.set(name, problem);
        }
    }
    for (const { name, problem } of checked?.problems ?? []) {
        problems.set(name, problem);
    }
    const sections = sectionsOf(snapshot);
    const shown = new Set(sections.flatMap((section) => section.fields.filter(visible).map((field) => field.name)));
    const unseen = Object.entries(answers).filter(([name]) => !shown.has(name));

    const touch = (name: string) => setTouched((current) => (current.has(name) ? current : new Set(current).add(name)));
    const markBusy = (name: string, reading: boolean) =>
        setBusy((current) => {
            if (current.has(name) === reading) {
                return current;
            }
            const next = new Set(current);
            if (reading) {
                next.add(name);
            } else {
                next.delete(name);
            }
            return next;
        });
    const problemOf = (field: AttributeFieldView) => {
        const problem = problems.get(field.name);
        if (answers[field.name]) {
            return answers[field.name] ?? null;
        }
        return problem && (submitted || touched.has(field.name)) ? strings.attributeProblem(problem, field.kind) : null;
    };

    return (
        <div className="flex flex-col gap-s4">
            {sections.map((section, index) => {
                const heading = `${headings}-${index}`;
                return (
                    <section key={section.title ?? ''} aria-labelledby={heading} className="flex flex-col gap-s3">
                        <h3 id={heading} className="border-b border-separator pb-s1 text-body font-semibold text-primary">
                            {section.title ?? strings.customAttributes}
                        </h3>
                        {section.title === null &&
                            snapshot.unsupported.map((label, at) => (
                                <UnsupportedRow key={`${at}-${label}`} label={label} target={target} disabled={disabled} />
                            ))}
                        {section.fields.filter(visible).map((field) => {
                            const Control = controls[field.kind as AttributeFieldKind];
                            return (
                                <Control
                                    key={field.name}
                                    field={field}
                                    value={values[field.name]}
                                    options={field.options}
                                    problem={problemOf(field)}
                                    disabled={disabled}
                                    changedAt={() => changedAt(field.name)}
                                    onChange={(next, at) => {
                                        if (at === undefined || at === changedAt(field.name)) {
                                            edit(field.name, next);
                                        }
                                    }}
                                    onTouch={() => touch(field.name)}
                                    onBusy={(reading) => markBusy(field.name, reading)}
                                />
                            );
                        })}
                    </section>
                );
            })}
            {unseen.map(([name, message]) => (
                <p key={name} role="alert" className="text-caption text-bad">
                    {message}
                </p>
            ))}
            {checked?.problems === null && (
                <p role="alert" className="text-caption text-bad">
                    {strings.attributeCheckFailed}
                </p>
            )}
        </div>
    );
}

const visible = (field: AttributeFieldView) => !field.hidden && field.kind !== null;
