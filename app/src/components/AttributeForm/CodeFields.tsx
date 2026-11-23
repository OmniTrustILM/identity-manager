import { strings } from '../../strings';
import { areaClass, FieldFrame, type FieldProps, ReadOnlyField, useFieldIds } from './Field';
import { textOf } from './values';

interface AreaProps extends FieldProps {
    kind: 'code' | 'object';
    placeholder: string;
}

function MonoArea({ kind, placeholder, field, value, problem, disabled, onChange, onTouch }: Readonly<AreaProps>) {
    const ids = useFieldIds(field, problem);
    const caption =
        kind === 'code' && field.language ? <span className="font-mono text-caption text-secondary">{field.language}</span> : null;
    if (field.readOnly) {
        return <ReadOnlyField field={field} text={textOf(value)} mono />;
    }
    return (
        <FieldFrame field={field} ids={ids} problem={problem} aside={caption}>
            <textarea
                {...ids.control}
                rows={6}
                spellCheck={false}
                autoCapitalize="off"
                autoCorrect="off"
                placeholder={placeholder}
                disabled={disabled}
                value={textOf(value)}
                onChange={(event) => onChange({ kind, value: event.target.value })}
                onBlur={onTouch}
                className={`${areaClass} font-mono`}
            />
        </FieldFrame>
    );
}

/** A block of code, with its language as a caption. */
export const CodeField = (props: Readonly<FieldProps>) => <MonoArea {...props} kind="code" placeholder={strings.enterScript} />;

/** An object, written as JSON. */
export const JsonField = (props: Readonly<FieldProps>) => <MonoArea {...props} kind="object" placeholder={strings.enterJson} />;
