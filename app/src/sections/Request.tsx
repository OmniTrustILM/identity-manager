import { type ReactNode, useCallback, useEffect, useId, useRef, useState } from 'react';
import {
    type AttributeFieldProblem,
    type AttributeFormView,
    type AttributeValue,
    closeForm,
    completeCertificate,
    type FollowView,
    followRequest,
    stopFollowingRequest,
    type KeyTypeId,
    openPreparedForms,
    openRequestForms,
    type PreparedView,
    type Platform,
    type RaProfileChoice,
    type RequestFailure,
    type RequestForms,
    type RequestFormsView,
    type RequestOffers,
    type RequestedView,
    requestCertificate,
    requestFailure,
    requestOffers,
    type StorageId,
    type SubjectKind,
} from '../bridge';
import { AttributeForm, type AttributeState } from '../components/AttributeForm/AttributeForm';
import { textOf } from '../components/AttributeForm/values';
import { TextField } from '../components/TextField/TextField';
import { Select } from '../components/Switch/Select';
import { BusyIcon, ExpiredIcon, ExpiringIcon, FineIcon, WarningIcon } from '../design-system/icons';
import { strings } from '../strings';

type FormKind = 'request' | 'issue' | 'custom';
type Step = 'profile' | 'attributes' | 'key' | 'review' | 'result';
type Phase = { kind: 'filling' } | { kind: 'requesting' } | { kind: 'followed'; requested: RequestedView };
type Refusal = { messages: string[]; problems: AttributeFieldProblem[] };

const stepOrder: Step[] = ['profile', 'attributes', 'key', 'review'];
const preparedOrder: Step[] = ['attributes', 'key', 'review'];
/** What ILM says when the challenge of a prepared certificate is wrong or can no longer be used. */
const challengeRefusals = [
    'The certificate registration challenge is invalid.',
    'The certificate registration challenge is required.',
    'The certificate registration authorization is locked after too many failed attempts.',
    'The certificate registration issuance window has expired.',
    'An authorization secret was presented but the certificate has no active registration authorization to verify it against.',
];
/** The parts of a prepared subject that name the certificate; the others are alternative names. */
const nameKinds: SubjectKind[] = [
    'commonName',
    'organization',
    'organizationalUnit',
    'country',
    'state',
    'locality',
    'serialNumber',
    'domainComponent',
    'other',
];
const kinds: FormKind[] = ['request', 'issue', 'custom'];
const groupNames: Record<FormKind, string> = {
    request: strings.certificateRequestGroup,
    issue: strings.raProfileGroup,
    custom: strings.customAttributes,
};
const followEvery = 2000;
const followTries = 30;
const preferredType = 'ecP256';
const noProblems: AttributeFieldProblem[] = [];

const primary = 'h-button shrink-0 whitespace-nowrap rounded-control bg-accent px-s3 text-body text-on-accent disabled:opacity-disabled';
const secondary = 'h-button shrink-0 whitespace-nowrap rounded-control border border-button-edge bg-button px-s3 text-body text-primary';

/** The key type to start with in a storage: EC P-256 when it is offered, else the first. */
const startingType = (types: KeyTypeId[]) => (types.includes(preferredType) ? preferredType : (types[0] ?? ''));

/** What a value says in words: the label of a chosen option, else the text typed; nothing for what has no plain text. */
function spoken(form: AttributeFormView, name: string, value: AttributeValue | undefined): string {
    const field = form.groups.flatMap((group) => group.fields).find((candidate) => candidate.name === name);
    if (value?.kind === 'option') {
        return field?.options.find((option) => option.key === value.value)?.label ?? value.value;
    }
    return textOf(value).trim();
}

/** The filled values of the request form, in the order of its fields, as one line. */
function subjectOf(form: AttributeFormView | null, values: AttributeState['values'] | undefined): string {
    if (!form || !values) {
        return '';
    }
    return form.groups
        .flatMap((group) => group.fields.filter((field) => !field.hidden && field.kind !== 'info'))
        .map((field) => spoken(form, field.name, values[field.name]))
        .filter((text) => text !== '')
        .join(', ');
}

const preparedSubject = (prepared: PreparedView) =>
    prepared.subject
        .filter((part) => nameKinds.includes(part.kind))
        .map((part) => part.value)
        .join(', ');

function Stepper({ step, steps }: Readonly<{ step: Step; steps: Step[] }>) {
    const at = steps.indexOf(step);
    return (
        <ol aria-label={strings.requestSteps} className="flex items-center gap-s2">
            {steps.map((name, index) => {
                const done = index < at;
                const current = index === at;
                return (
                    <li key={name} aria-current={current ? 'step' : undefined} className="flex flex-1 items-center gap-s2 last:flex-none">
                        <span
                            aria-hidden
                            className={`flex size-icon shrink-0 items-center justify-center rounded-full border text-caption ${done || current ? 'border-accent bg-accent text-on-accent' : 'border-separator text-secondary'}`}
                        >
                            {done ? '✓' : index + 1}
                        </span>
                        <span className={`text-body ${current ? 'text-primary' : 'text-secondary'}`}>
                            {strings.requestStepNames[stepOrder.indexOf(name)]}
                            {done && <span className="sr-only">{`, ${strings.stepDone}`}</span>}
                        </span>
                        {index < steps.length - 1 && <span aria-hidden className="h-px min-w-s3 flex-1 bg-separator" />}
                    </li>
                );
            })}
        </ol>
    );
}

interface Card {
    value: string;
    title: string;
    lines: string[];
    chip?: string;
}

function Cards({
    label,
    name,
    cards,
    value,
    onChange,
}: Readonly<{ label: string; name: string; cards: Card[]; value: string; onChange: (value: string) => void }>) {
    return (
        <div role="radiogroup" aria-label={label} className="flex flex-col gap-s3">
            {cards.map((card) => (
                <label
                    key={card.value}
                    className="flex cursor-pointer items-center gap-s3 rounded-control border border-separator px-s3 py-s3 has-checked:border-accent has-checked:bg-row-current"
                >
                    <input
                        type="radio"
                        name={name}
                        value={card.value}
                        checked={card.value === value}
                        onChange={() => onChange(card.value)}
                        className="size-icon shrink-0 accent-accent"
                    />
                    <span className="flex min-w-0 flex-1 flex-col">
                        <span className="text-body text-primary">{card.title}</span>
                        {card.lines.map((line) => (
                            <span key={line} className="text-caption text-secondary">
                                {line}
                            </span>
                        ))}
                    </span>
                    {card.chip && <span className="rounded-control bg-row-current px-s2 text-caption text-primary">{card.chip}</span>}
                </label>
            ))}
        </div>
    );
}

function Rows({ rows }: Readonly<{ rows: [string, string][] }>) {
    return (
        <dl className="flex flex-col divide-y divide-separator rounded-control border border-separator">
            {rows.map(([name, text], at) => (
                <div key={`${at}-${name}`} className="flex gap-s3 px-s3 py-s2 text-body">
                    <dt className="w-1/3 shrink-0 text-secondary">{name}</dt>
                    <dd className="min-w-0 flex-1 text-primary">{text}</dd>
                </div>
            ))}
        </dl>
    );
}

/** What the administrator registered for a certificate, as it stands and cannot be changed. */
function PreparedGroup({ prepared }: Readonly<{ prepared: PreparedView }>) {
    const id = useId();
    const rows: [string, string][] = prepared.subject.map((part) => [
        part.kind === 'other' && part.oid ? part.oid : strings.subjectLabels[part.kind],
        part.value,
    ]);
    return (
        <section aria-labelledby={id} className="flex flex-col gap-s3">
            <h3 id={id} className="border-b border-separator pb-s1 text-body font-semibold text-primary">
                {strings.preparedBy}
            </h3>
            <Rows rows={[...rows, [strings.raProfileLabel, prepared.raProfile.name]]} />
        </section>
    );
}

/** One of the forms of a request, under the heading of its kind; it keeps the state of its form current. */
function FormGroup({
    kind,
    form,
    problems,
    submitted,
    disabled,
    onState,
}: Readonly<{
    kind: FormKind;
    form: AttributeFormView;
    problems: AttributeFieldProblem[];
    submitted: boolean;
    disabled: boolean;
    onState: (kind: FormKind, state: AttributeState) => void;
}>) {
    const change = useCallback((state: AttributeState) => onState(kind, state), [kind, onState]);
    return (
        <AttributeForm
            form={form}
            target="addToIlm"
            disabled={disabled}
            submitted={submitted}
            serverProblems={problems}
            untitled={groupNames[kind]}
            onChange={change}
        />
    );
}

function Refused({ refusal }: Readonly<{ refusal: Refusal }>) {
    return (
        <div role="alert" className="flex items-start gap-s2 rounded-control border border-bad px-s3 py-s2">
            <WarningIcon aria-hidden className="mt-[2px] size-icon shrink-0 text-bad" />
            <div className="flex min-w-0 flex-col">
                <p className="text-body font-semibold text-primary">{strings.requestRefused}</p>
                {refusal.messages.length > 0 ? (
                    refusal.messages.map((message) => (
                        <p key={message} className="text-body text-secondary">
                            {message}
                        </p>
                    ))
                ) : (
                    <p className="text-body text-secondary">{strings.attributesNeedAttention}</p>
                )}
            </div>
        </div>
    );
}

/** How a followed request ended, or that it is still going. */
function Outcome({ view, label, platform }: Readonly<{ view: FollowView; label: string; platform: Platform }>) {
    let Icon = ExpiringIcon;
    let tone = 'text-accent';
    let title: string = strings.issuing;
    let lines: string[] = [strings.installWhenIssued];
    let rows: [string, string][] = [];
    if (view.state === 'installed') {
        Icon = FineIcon;
        tone = 'text-fine';
        title = strings.installedTitle;
        lines = [strings.installedIn(label, platform)];
        rows = [
            [strings.requestValidUntil, strings.date(view.validUntil)],
            [strings.reviewKey, strings.storageName(view.storage, platform)],
        ];
    } else if (view.state === 'waiting' && view.stage === 'pendingApproval') {
        title = strings.waitingForApproval;
    } else if (view.state === 'ended') {
        Icon = ExpiredIcon;
        tone = 'text-bad';
        title = view.reason === 'rejected' ? strings.requestRejected : strings.requestNotIssued;
        lines = [];
    } else if (view.state === 'notInstalled') {
        Icon = WarningIcon;
        tone = 'text-attention';
        title = view.cause === 'otherKey' ? strings.requestOtherKey : strings.requestIssuedNotInstalled;
        lines = [];
    }
    return (
        <div className="flex flex-1 flex-col items-center justify-center gap-s3 text-center">
            <Icon aria-hidden className={`size-toolbar-icon ${tone}`} />
            <h3 key={title} ref={focusNode} tabIndex={-1} className="text-title font-semibold text-primary outline-none">
                {title}
            </h3>
            {lines.map((line) => (
                <p key={line} className="text-body text-secondary">
                    {line}
                </p>
            ))}
            {rows.length > 0 && (
                <div className="w-full">
                    <Rows rows={rows} />
                </div>
            )}
        </div>
    );
}

/** Puts the focus on a heading when it appears, so that a step announces itself. */
const focusNode = (node: HTMLElement | null) => node?.focus();

const settled = (view: FollowView) => view.state === 'installed' || view.state === 'ended' || view.state === 'notInstalled';

/**
 * The sheet that asks ILM for a certificate: the RA Profile, the attributes ILM wants, where the private key lives, a
 * review, and then how the request fares. Nothing is created before the review is confirmed.
 */
export function Request({
    profiles = [],
    prepared,
    platform,
    onClose,
}: Readonly<{
    profiles?: RaProfileChoice[];
    /** A certificate registered in advance to complete: the sheet has no profile step and shows what was registered. */
    prepared?: PreparedView;
    platform: Platform;
    onClose: () => void;
}>) {
    const titleId = useId();
    const challengeId = useId();
    const panel = useRef<HTMLDialogElement>(null);
    const challengeField = useRef<HTMLInputElement>(null);
    const single = prepared !== undefined || profiles.length === 1;
    const [step, setStep] = useState<Step>(single ? 'attributes' : 'profile');
    const [profile, setProfile] = useState(profiles[0]?.uuid ?? '');
    const [opened, setOpened] = useState<string | null>(prepared?.uuid ?? (single ? (profiles[0]?.uuid ?? null) : null));
    const [challenge, setChallenge] = useState('');
    const [challengeProblems, setChallengeProblems] = useState<string[]>([]);
    const [challengeAsked, setChallengeAsked] = useState(false);
    const [forms, setForms] = useState<RequestFormsView | null>(null);
    const [formsFailed, setFormsFailed] = useState(false);
    const [states, setStates] = useState<Partial<Record<FormKind, AttributeState>>>({});
    const [offers, setOffers] = useState<RequestOffers | null>(null);
    const [offersFailed, setOffersFailed] = useState(false);
    const [storage, setStorage] = useState<StorageId | null>(null);
    const [keyType, setKeyType] = useState('');
    const [phase, setPhase] = useState<Phase>({ kind: 'filling' });
    const [refusal, setRefusal] = useState<Refusal | null>(null);
    const [problem, setProblem] = useState<string | null>(null);
    const [submitted, setSubmitted] = useState(false);
    const [view, setView] = useState<FollowView>({ state: 'unknown' });
    /** Set once ILM took the request: the forms are used up then and nothing is left to close. */
    const consumed = useRef(false);
    const mounted = useRef(false);

    const onState = useCallback((kind: FormKind, state: AttributeState) => setStates((current) => ({ ...current, [kind]: state })), []);

    useEffect(() => {
        const before = document.activeElement as HTMLElement | null;
        mounted.current = true;
        panel.current?.showModal();
        return () => {
            mounted.current = false;
            before?.focus();
        };
    }, []);

    useEffect(() => {
        if (opened === null) {
            return;
        }
        let current = true;
        let loaded: RequestFormsView | null = null;
        (prepared ? openPreparedForms(opened) : openRequestForms(opened)).then(
            (result) => {
                loaded = result;
                if (current) {
                    setForms(result);
                } else {
                    closeAll(result);
                }
            },
            () => current && setFormsFailed(true),
        );
        return () => {
            current = false;
            if (loaded && !consumed.current) {
                closeAll(loaded);
            }
        };
    }, [opened, prepared]);

    useEffect(() => {
        if (step !== 'key' || offers !== null || offersFailed) {
            return;
        }
        let current = true;
        requestOffers().then(
            (loaded) => {
                if (!current) {
                    return;
                }
                const first = loaded.storages.find((offer) => offer.storage === loaded.defaultStorage) ?? loaded.storages[0];
                setOffers(loaded);
                setStorage(first?.storage ?? null);
                setKeyType(startingType(first?.keyTypes ?? []));
            },
            () => current && setOffersFailed(true),
        );
        return () => {
            current = false;
        };
    }, [step, offers, offersFailed]);

    useEffect(() => {
        if (challengeProblems.length > 0) {
            challengeField.current?.focus();
        }
    }, [challengeProblems]);

    const requested = phase.kind === 'followed' ? phase.requested.certificate : null;
    useEffect(() => {
        if (requested === null) {
            return;
        }
        let current = true;
        let tries = 0;
        let timer: ReturnType<typeof setTimeout> | undefined;
        const release = () => stopFollowingRequest(requested).catch(() => undefined);
        const again = () => {
            tries += 1;
            if (tries < followTries) {
                timer = setTimeout(poll, followEvery);
            } else {
                void release();
            }
        };
        const poll = () =>
            followRequest(requested).then(
                (answer) => {
                    if (!current) {
                        return;
                    }
                    setView(answer);
                    if (answer.state === 'notInstalled') {
                        void release();
                    } else if (!settled(answer)) {
                        again();
                    }
                },
                () => current && again(),
            );
        void poll();
        return () => {
            current = false;
            clearTimeout(timer);
            void release();
        };
    }, [requested]);

    const busy = phase.kind === 'requesting';
    const offer = offers?.storages.find((candidate) => candidate.storage === storage);
    const present = kinds.filter((kind) => forms?.[kind]);
    const formsReady = forms !== null && present.every((kind) => states[kind]?.ready === true && !states[kind]?.blocked);
    const keyReady = storage !== null && offer?.keyTypes.includes(keyType) === true;
    const blocked = present.some((kind) => states[kind]?.blocked);
    const chosen = profiles.find((candidate) => candidate.uuid === profile);
    const needsChallenge = prepared?.registration?.state === 'active' || challengeAsked;

    const goTo = (next: Step) => {
        setProblem(null);
        setStep(next);
    };
    const leaveProfile = () => {
        setOpened(null);
        setForms(null);
        setFormsFailed(false);
        setStates({});
        setRefusal(null);
        setSubmitted(false);
        goTo('profile');
    };
    const chooseStorage = (next: string) => {
        const found = offers?.storages.find((candidate) => candidate.storage === next);
        setStorage(found?.storage ?? null);
        setKeyType(startingType(found?.keyTypes ?? []));
    };

    const request = () => {
        if (!forms || storage === null) {
            return;
        }
        const filled: RequestForms = {};
        for (const kind of present) {
            const form = forms[kind];
            const state = states[kind];
            if (form && state) {
                filled[kind] = { id: form.id, values: state.values };
            }
        }
        setProblem(null);
        setRefusal(null);
        setSubmitted(true);
        setChallengeProblems([]);
        setPhase({ kind: 'requesting' });
        const sending = prepared
            ? completeCertificate(prepared.uuid, filled, storage, keyType, needsChallenge ? challenge : null)
            : requestCertificate(profile, filled, storage, keyType);
        setChallenge('');
        sending.then(
            (done) => {
                consumed.current = true;
                if (!mounted.current) {
                    stopFollowingRequest(done.certificate).catch(() => undefined);
                    return;
                }
                setPhase({ kind: 'followed', requested: done });
                setStep('result');
            },
            (error) => {
                if (!mounted.current) {
                    closeAll(forms);
                    return;
                }
                const failure: RequestFailure = requestFailure(error);
                setPhase({ kind: 'filling' });
                if (prepared && failure.kind === 'refused' && failure.messages.length > 0 && failure.messages.every(isChallengeRefusal)) {
                    setChallengeAsked(true);
                    setChallengeProblems(failure.messages);
                } else if (failure.kind === 'message') {
                    setProblem(failure.message || strings.requestFailed);
                } else {
                    setRefusal({
                        messages: failure.kind === 'refused' ? failure.messages : [],
                        problems: failure.kind === 'problems' ? failure.problems : noProblems,
                    });
                    setStep('attributes');
                }
            },
        );
    };

    const footer = (confirm: ReactNode, back: ReactNode) => (
        <div className="flex items-center justify-end gap-s2 border-t border-separator pt-s3">
            {platform === 'macos' ? (
                <>
                    {back}
                    {confirm}
                </>
            ) : (
                <>
                    {confirm}
                    {back}
                </>
            )}
        </div>
    );
    const wide = platform === 'macos' ? '' : ' flex-1';
    const cancelButton = (
        <button type="button" onClick={onClose} className={secondary + wide}>
            {strings.cancel}
        </button>
    );
    const backTo = (target: () => void) => (
        <button type="button" onClick={target} className={secondary + wide}>
            {strings.back}
        </button>
    );
    const continueTo = (disabled: boolean, target: () => void) => (
        <button type="button" disabled={disabled} onClick={target} className={primary + wide}>
            {strings.continue}
        </button>
    );

    const storageCards: Card[] = (offers?.storages ?? []).map((candidate) => ({
        value: candidate.storage,
        title: strings.storageName(candidate.storage, platform),
        lines: [strings.storageDescription(candidate.storage, platform)],
        chip: candidate.storage === offers?.defaultStorage ? strings.recommended : undefined,
    }));
    const where = strings.keyPlace(storage ?? '', platform);
    const subject = prepared ? preparedSubject(prepared) : subjectOf(forms?.request ?? null, states.request?.values);
    const title = (text: string) => (
        <h3 key={text} ref={focusNode} tabIndex={-1} className="text-title font-semibold text-primary outline-none">
            {text}
        </h3>
    );

    let body: ReactNode = null;
    let actions: ReactNode = null;
    if (step === 'result' && phase.kind === 'followed') {
        body = <Outcome view={view} label={phase.requested.label} platform={platform} />;
        actions = footer(
            <button type="button" onClick={onClose} className={primary + wide}>
                {strings.done}
            </button>,
            null,
        );
    } else if (step === 'profile') {
        body = (
            <>
                {title(strings.chooseProfile)}
                <p className="text-body text-secondary">{strings.chooseProfileHint}</p>
                <Cards
                    label={strings.profiles}
                    name="profile"
                    value={profile}
                    onChange={setProfile}
                    cards={profiles.map((candidate) => ({
                        value: candidate.uuid,
                        title: candidate.name,
                        lines: [candidate.description, candidate.authority ? strings.authorityNamed(candidate.authority) : null].filter(
                            (line): line is string => line !== null && line !== '',
                        ),
                    }))}
                />
            </>
        );
        actions = footer(
            continueTo(!chosen, () => {
                setOpened(profile);
                goTo('attributes');
            }),
            cancelButton,
        );
    } else if (step === 'key') {
        body = (
            <>
                {title(strings.keyHome)}
                <p className="text-body text-secondary">{strings.keyStaysHere(platform)}</p>
                {offersFailed && (
                    <p role="alert" className="text-body text-bad">
                        {strings.offersFailed}
                    </p>
                )}
                {offers === null && !offersFailed && <p className="text-body text-secondary">{strings.offersLoading}</p>}
                {offers !== null && offers.storages.length === 0 && <p className="text-body text-secondary">{strings.noKeyStorage}</p>}
                {offer && (
                    <>
                        <Cards
                            label={strings.keyStorages}
                            name="storage"
                            value={storage ?? ''}
                            onChange={chooseStorage}
                            cards={storageCards}
                        />
                        <KeyTypeChoice types={offer.keyTypes} value={keyType} onChange={setKeyType} />
                    </>
                )}
            </>
        );
        actions = footer(
            continueTo(!keyReady, () => goTo('review')),
            backTo(() => goTo('attributes')),
        );
    } else if (step === 'review') {
        body = (
            <>
                {title(strings.reviewTitle)}
                {problem !== null && (
                    <p role="alert" className="rounded-control border border-bad px-s3 py-s2 text-body text-bad">
                        {problem}
                    </p>
                )}
                <Rows
                    rows={[
                        prepared ? [strings.reviewCertificate, prepared.name] : [strings.reviewProfile, chosen?.name ?? ''],
                        [strings.reviewSubject, subject],
                        ...(prepared ? [[strings.raProfileLabel, prepared.raProfile.name] as [string, string]] : []),
                        [strings.reviewKey, strings.reviewNewKey(where)],
                        [strings.reviewKeyType, strings.keyTypeNames[keyType] ?? keyType],
                        [strings.reviewInstalledIn, strings.installedPlace(platform)],
                    ]}
                />
                {needsChallenge && (
                    <div className="flex flex-col gap-s1">
                        <label htmlFor={challengeId} className="text-caption font-semibold text-secondary">
                            {strings.challenge}
                        </label>
                        <TextField
                            id={challengeId}
                            ref={challengeField}
                            type="password"
                            autoComplete="off"
                            disabled={busy}
                            value={challenge}
                            aria-invalid={challengeProblems.length > 0 ? true : undefined}
                            aria-describedby={[`${challengeId}-hint`, challengeProblems.length > 0 && `${challengeId}-problem`]
                                .filter(Boolean)
                                .join(' ')}
                            onChange={(event) => {
                                setChallenge(event.target.value);
                                setChallengeProblems([]);
                            }}
                        />
                        <p id={`${challengeId}-hint`} className="text-caption text-secondary">
                            {strings.challengeHint}
                        </p>
                        {challengeProblems.length > 0 && (
                            <div id={`${challengeId}-problem`} role="alert" className="flex flex-col text-caption text-bad">
                                {challengeProblems.map((message) => (
                                    <p key={message}>{message}</p>
                                ))}
                            </div>
                        )}
                    </div>
                )}
                <ol aria-label={strings.requestPlanName} className="flex flex-col gap-s2">
                    {strings.requestPlan(where).map((line, index) => (
                        <li key={line} className="flex items-center gap-s2 text-body text-secondary">
                            <span
                                aria-hidden
                                className="flex size-icon shrink-0 items-center justify-center rounded-full bg-row-current text-caption"
                            >
                                {index + 1}
                            </span>
                            {line}
                        </li>
                    ))}
                </ol>
            </>
        );
        actions = footer(
            busy ? (
                <button type="button" disabled className={`${primary} flex items-center justify-center gap-s2${wide}`}>
                    <BusyIcon aria-hidden className="size-icon motion-safe:animate-spin" />
                    {strings.requesting}
                </button>
            ) : (
                <button type="button" disabled={needsChallenge && challenge === ''} onClick={request} className={primary + wide}>
                    {prepared ? strings.issueCertificate : strings.requestCertificate}
                </button>
            ),
            <button type="button" disabled={busy} onClick={() => goTo('key')} className={`${secondary}${wide} disabled:opacity-disabled`}>
                {strings.back}
            </button>,
        );
    }

    const attributes = (
        <div hidden={step !== 'attributes'} className="flex flex-col gap-s3">
            {step === 'attributes' && title(strings.fillAttributes)}
            {refusal && <Refused refusal={refusal} />}
            {prepared && <PreparedGroup prepared={prepared} />}
            {formsFailed && (
                <p role="alert" className="text-body text-bad">
                    {strings.requestFormsFailed}
                </p>
            )}
            {!forms && !formsFailed && <p className="text-body text-secondary">{strings.requestFormsLoading}</p>}
            {forms &&
                present.map((kind) => (
                    <FormGroup
                        key={`${opened}-${kind}`}
                        kind={kind}
                        form={forms[kind] as AttributeFormView}
                        problems={refusal?.problems ?? noProblems}
                        submitted={submitted}
                        disabled={busy}
                        onState={onState}
                    />
                ))}
        </div>
    );
    const attributeActions = footer(
        continueTo(!formsReady || blocked, () => {
            setRefusal(null);
            goTo('key');
        }),
        single ? cancelButton : backTo(leaveProfile),
    );

    return (
        <dialog
            ref={panel}
            tabIndex={-1}
            aria-labelledby={titleId}
            onCancel={(event) => {
                event.preventDefault();
                if (!busy) {
                    onClose();
                }
            }}
            className="m-auto box-content flex h-wizard max-h-[85vh] w-wizard flex-col gap-s3 rounded-window border border-separator bg-surface p-s5 text-primary backdrop:bg-primary/40"
        >
            <h2 id={titleId} className="text-title font-semibold text-primary">
                {prepared ? strings.issueTitle(prepared.name) : strings.requestTitle}
            </h2>
            {step !== 'result' && <Stepper step={step} steps={prepared ? preparedOrder : stepOrder} />}
            <div className="flex min-h-0 flex-1 flex-col gap-s3 overflow-y-auto">
                {attributes}
                {body}
            </div>
            {step === 'attributes' ? attributeActions : actions}
        </dialog>
    );
}

const isChallengeRefusal = (message: string) => challengeRefusals.includes(message);

function closeAll(forms: RequestFormsView) {
    for (const kind of kinds) {
        const form = forms[kind];
        if (form) {
            closeForm(form.id).catch(() => undefined);
        }
    }
}

function KeyTypeChoice({ types, value, onChange }: Readonly<{ types: KeyTypeId[]; value: string; onChange: (value: string) => void }>) {
    const id = useId();
    return (
        <div className="flex flex-col gap-s1">
            <label htmlFor={id} className="text-caption font-semibold text-secondary">
                {strings.keyType}
            </label>
            <Select id={id} value={value} options={types} label={(type) => strings.keyTypeNames[type] ?? type} onChange={onChange} fill />
        </div>
    );
}
