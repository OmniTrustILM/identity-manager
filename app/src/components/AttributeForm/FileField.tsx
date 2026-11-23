import { useEffect, useRef, useState } from 'react';
import type { AttributeValue } from '../../bridge';
import { strings } from '../../strings';
import { FieldFrame, type FieldProps, ReadOnlyField, useFieldIds } from './Field';
import { base64Size, readable } from './values';

/** The largest file the form takes, as the core checks it. */
const maxBytes = 1024 * 1024;

const button =
    'h-control shrink-0 rounded-control border border-button-edge bg-button px-s3 text-body text-primary disabled:opacity-disabled';

function readBase64(file: File): Promise<string> {
    return new Promise((resolve, reject) => {
        const reader = new FileReader();
        reader.onload = () => {
            const result = reader.result;
            if (typeof result === 'string') {
                resolve(result.replace(/^[^,]*,/, ''));
            } else {
                reject(new Error('the file cannot be read'));
            }
        };
        reader.onerror = () => reject(new Error('the file cannot be read'));
        reader.readAsDataURL(file);
    });
}

/** A file, read in the web view as base64 and shown by its name and size. */
export function FileField({ field, value, options, problem, disabled, changedAt, onChange, onTouch, onBusy }: Readonly<FieldProps>) {
    const ids = useFieldIds(field, problem);
    const input = useRef<HTMLInputElement>(null);
    const chooser = useRef<HTMLButtonElement>(null);
    /** What went wrong with the file chosen when the field had last changed at this moment; void once the field changes. */
    const [local, setLocal] = useState<{ at: number; fault: 'tooLarge' | 'empty' | 'unreadable' } | null>(null);
    const selection = useRef(0);
    const busy = useRef(onBusy);
    busy.current = onBusy;
    useEffect(
        () => () => {
            selection.current++;
            busy.current(false);
        },
        [],
    );
    const fault = local?.at === changedAt() ? local.fault : null;
    let shown = problem;
    if (fault === 'tooLarge') {
        shown = strings.attributeProblem({ kind: 'fileTooLarge', max: maxBytes }, 'file');
    } else if (fault === 'empty') {
        shown = strings.fileEmpty;
    } else if (fault === 'unreadable') {
        shown = strings.fileUnreadable;
    }
    const file = value?.kind === 'file' ? value.value : null;
    if (field.readOnly) {
        return <ReadOnlyField field={field} text={readable(field, value, options)} />;
    }

    const choose = async (chosen: File | undefined) => {
        onTouch();
        if (!chosen) {
            return;
        }
        const mine = ++selection.current;
        const at = changedAt();
        if (chosen.size > maxBytes || chosen.size === 0) {
            setLocal({ at, fault: chosen.size === 0 ? 'empty' : 'tooLarge' });
            onBusy(true);
            onChange(undefined);
            return;
        }
        setLocal(null);
        onBusy(true);
        let next: AttributeValue | undefined;
        try {
            next = {
                kind: 'file',
                value: { name: chosen.name, mime: chosen.type || 'application/octet-stream', content: await readBase64(chosen) },
            };
        } catch {
            next = undefined;
        }
        if (mine !== selection.current) {
            return;
        }
        if (next) {
            onBusy(false);
        } else {
            // The form stays unfit to send until another file is chosen or the form replaces the field.
            setLocal({ at, fault: 'unreadable' });
        }
        onChange(next, at);
    };

    const remove = () => {
        onTouch();
        selection.current++;
        setLocal(null);
        onBusy(false);
        onChange(undefined);
        chooser.current?.focus();
    };

    return (
        <FieldFrame field={field} ids={{ ...ids, problemId: shown ? `${ids.id}-problem` : null }} problem={shown} spoken>
            <div aria-invalid={shown ? true : undefined} className="flex items-center gap-s2">
                <input
                    ref={input}
                    type="file"
                    hidden
                    tabIndex={-1}
                    disabled={disabled}
                    onChange={(event) => {
                        void choose(event.target.files?.[0]);
                        event.target.value = '';
                    }}
                />
                <button
                    ref={chooser}
                    id={ids.id}
                    type="button"
                    tabIndex={0}
                    aria-labelledby={`${ids.labelId} ${ids.id}`}
                    aria-describedby={[ids.hintId, shown ? `${ids.id}-problem` : null].filter(Boolean).join(' ') || undefined}
                    disabled={disabled}
                    onClick={() => input.current?.click()}
                    className={`${button} ${shown ? 'border-bad' : ''}`}
                >
                    {strings.chooseFile}
                </button>
                {(file || fault) && !disabled ? (
                    <button type="button" tabIndex={0} aria-label={strings.removeFile(field.label)} onClick={remove} className={button}>
                        {strings.remove}
                    </button>
                ) : null}
                {file ? (
                    <span className="flex min-w-0 flex-col text-body text-primary">
                        <span className="truncate">{file.name}</span>
                        <span className="text-caption text-secondary">{strings.fileSize(base64Size(file.content))}</span>
                    </span>
                ) : (
                    <span className="text-body text-tertiary">{strings.noFileChosen}</span>
                )}
            </div>
        </FieldFrame>
    );
}
