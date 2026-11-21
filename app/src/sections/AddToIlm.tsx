import { useEffect, useId, useRef, useState } from 'react';
import { type AddChoicesView, type AddResultView, addToIlm, addToIlmChoices, type LocalCertificateView } from '../bridge';
import { BusyIcon, ExpiredIcon, FineIcon, LockIcon, WarningIcon } from '../design-system/icons';
import { Select } from '../components/Switch/Select';
import { strings } from '../strings';

type System = 'macos' | 'windows';
type Phase = { kind: 'choosing' } | { kind: 'adding' } | { kind: 'done'; results: AddResultView[] };

const primary = 'h-button rounded-control bg-accent px-s3 text-body text-on-accent disabled:opacity-disabled';
const secondary = 'h-button rounded-control border border-button-edge bg-button px-s3 text-body text-primary';
const none = '';

/** How the add of one certificate ended, in words, with the icon and colour that go with it. */
function resultLook({ outcome, messages }: AddResultView) {
    const reasons = messages.join(' ');
    switch (outcome) {
        case 'addedNotManaged':
            return { Icon: WarningIcon, tone: 'text-attention', text: strings.addedNotManaged(reasons) };
        case 'notAdded':
            return { Icon: ExpiredIcon, tone: 'text-bad', text: strings.notAdded(reasons) };
        default:
            return { Icon: FineIcon, tone: 'text-fine', text: strings.added };
    }
}

function Results({ results, certificates }: Readonly<{ results: AddResultView[]; certificates: LocalCertificateView[] }>) {
    return (
        <ul aria-label={strings.addResults} className="flex flex-col divide-y divide-separator rounded-control border border-separator">
            {results.map((result) => {
                const { Icon, tone, text } = resultLook(result);
                const name = certificates.find((certificate) => certificate.fingerprint === result.fingerprint)?.name ?? result.fingerprint;
                return (
                    <li key={result.fingerprint} className="flex items-start gap-s2 px-s3 py-s2">
                        <Icon aria-hidden className={`mt-[2px] size-icon shrink-0 ${tone}`} />
                        <div className="flex min-w-0 flex-col">
                            <span className="text-body text-primary">{name}</span>
                            <span className={`text-caption ${tone}`}>{text}</span>
                        </div>
                    </li>
                );
            })}
        </ul>
    );
}

function Choice({
    id,
    label,
    value,
    options,
    names,
    note,
    disabled,
    onChange,
}: Readonly<{
    id: string;
    label: string;
    value: string;
    options: string[];
    names: Record<string, string>;
    note?: string;
    disabled: boolean;
    onChange: (value: string) => void;
}>) {
    return (
        <div className="flex flex-col gap-s1">
            <label htmlFor={id} className="text-caption font-semibold text-secondary">
                {label}
            </label>
            <Select
                id={id}
                value={value}
                options={options}
                label={(option) => names[option] ?? strings.none}
                onChange={onChange}
                aria-describedby={note ? `${id}-note` : undefined}
                fill
                disabled={disabled}
            />
            {note && (
                <p id={`${id}-note`} className="text-caption text-secondary">
                    {note}
                </p>
            )}
        </div>
    );
}

/**
 * The question that uploads certificates of this computer to ILM: which ones, and the group and RA Profile where ILM lets
 * the person choose them. While it works it cannot be withdrawn; afterwards it says how each certificate fared.
 */
export function AddToIlm({
    certificates,
    system,
    onClose,
}: Readonly<{ certificates: LocalCertificateView[]; system: System; onClose: () => void }>) {
    const titleId = useId();
    const groupId = useId();
    const profileId = useId();
    const panel = useRef<HTMLDialogElement>(null);
    const primaryButton = useRef<HTMLButtonElement>(null);
    const [choices, setChoices] = useState<AddChoicesView | null>(null);
    const [checked, setChecked] = useState(() => new Set(certificates.map((certificate) => certificate.fingerprint)));
    const [group, setGroup] = useState(none);
    const [profile, setProfile] = useState(none);
    const [phase, setPhase] = useState<Phase>({ kind: 'choosing' });
    const [problem, setProblem] = useState<string | null>(null);
    const ready = choices !== null;

    useEffect(() => {
        let current = true;
        addToIlmChoices().then(
            (loaded) => current && setChoices(loaded),
            () => current && setChoices({ groups: null, raProfiles: null }),
        );
        return () => {
            current = false;
        };
    }, []);

    useEffect(() => {
        if (!ready) {
            return;
        }
        const before = document.activeElement as HTMLElement | null;
        panel.current?.showModal();
        return () => before?.focus();
    }, [ready]);

    useEffect(() => {
        if (phase.kind === 'adding') {
            panel.current?.focus();
        } else if (ready) {
            primaryButton.current?.focus();
        }
    }, [phase.kind, ready]);

    if (!choices) {
        return null;
    }

    const selected = certificates.filter((certificate) => checked.has(certificate.fingerprint));
    const busy = phase.kind === 'adding';
    const toggle = (fingerprint: string, on: boolean) =>
        setChecked((current) => {
            const next = new Set(current);
            if (on) {
                next.add(fingerprint);
            } else {
                next.delete(fingerprint);
            }
            return next;
        });

    const add = () => {
        setProblem(null);
        setPhase({ kind: 'adding' });
        addToIlm(
            selected.map((certificate) => certificate.fingerprint),
            group || null,
            profile || null,
        ).then(
            (results) => setPhase({ kind: 'done', results }),
            (error) => {
                setProblem(String(error) || strings.addFailed);
                setPhase({ kind: 'choosing' });
            },
        );
    };

    const groups = Object.fromEntries((choices.groups ?? []).map((choice) => [choice.uuid, choice.name]));
    const profiles = Object.fromEntries((choices.raProfiles ?? []).map((choice) => [choice.uuid, choice.name]));
    const addButton = (
        <button ref={primaryButton} tabIndex={0} type="button" disabled={selected.length === 0} onClick={add} className={primary}>
            {strings.addCount(selected.length)}
        </button>
    );
    const cancelButton = (
        <button tabIndex={0} type="button" onClick={onClose} className={secondary}>
            {strings.cancel}
        </button>
    );

    return (
        <dialog
            ref={panel}
            tabIndex={-1}
            aria-labelledby={titleId}
            onCancel={(event) => {
                event.preventDefault();
                if (phase.kind === 'choosing') {
                    onClose();
                }
            }}
            className="m-auto box-content flex max-h-[85vh] w-form flex-col gap-s3 overflow-auto rounded-window border border-separator bg-surface p-s5 text-primary backdrop:bg-primary/40"
        >
            <h2 id={titleId} className="text-title font-semibold text-primary">
                {strings.addTitle(certificates.length)}
            </h2>
            {phase.kind === 'done' ? (
                <>
                    <Results results={phase.results} certificates={certificates} />
                    <button ref={primaryButton} tabIndex={0} type="button" onClick={onClose} className={`${primary} w-full`}>
                        {strings.close}
                    </button>
                </>
            ) : (
                <>
                    <p className="flex items-center gap-s1 text-body text-secondary">
                        <LockIcon aria-hidden className="size-icon shrink-0" />
                        {strings.keysStayHere(system)}
                    </p>
                    <fieldset disabled={busy} className="flex flex-col divide-y divide-separator rounded-control border border-separator">
                        <legend className="sr-only">{strings.certificatesToAdd}</legend>
                        {certificates.map((certificate) => (
                            <label key={certificate.fingerprint} className="flex items-start gap-s2 px-s3 py-s2">
                                <input
                                    type="checkbox"
                                    checked={checked.has(certificate.fingerprint)}
                                    onChange={(event) => toggle(certificate.fingerprint, event.target.checked)}
                                    className="mt-[3px] size-icon shrink-0 accent-accent"
                                />
                                <span className="flex min-w-0 flex-col text-body text-primary">
                                    {certificate.name}
                                    <span className="text-caption text-secondary">
                                        {certificate.issuerName}, {strings.expiresDate(strings.date(certificate.notAfter))}
                                    </span>
                                </span>
                            </label>
                        ))}
                    </fieldset>
                    {choices.groups && (
                        <Choice
                            id={groupId}
                            label={strings.group}
                            value={group}
                            options={[none, ...Object.keys(groups)]}
                            names={groups}
                            disabled={busy}
                            onChange={setGroup}
                        />
                    )}
                    {choices.raProfiles && (
                        <Choice
                            id={profileId}
                            label={strings.raProfile}
                            value={profile}
                            options={[none, ...Object.keys(profiles)]}
                            names={profiles}
                            note={strings.raProfileHint}
                            disabled={busy}
                            onChange={setProfile}
                        />
                    )}
                    {problem !== null && (
                        <p role="alert" className="text-caption text-bad">
                            {problem}
                        </p>
                    )}
                    <div className="flex justify-end gap-s2 pt-s2">
                        {busy ? (
                            <button type="button" disabled className={`${primary} flex items-center gap-s2`}>
                                <BusyIcon aria-hidden className="size-icon motion-safe:animate-spin" />
                                {strings.adding}
                            </button>
                        ) : (
                            <>
                                {system === 'macos' ? cancelButton : addButton}
                                {system === 'macos' ? addButton : cancelButton}
                            </>
                        )}
                    </div>
                </>
            )}
        </dialog>
    );
}
