import { clearMocks, mockIPC } from '@tauri-apps/api/mocks';
import { act } from 'react';
import { createRoot, type Root } from 'react-dom/client';
import { afterEach, beforeEach, expect, test, vi } from 'vitest';
import { attributeField, attributeForm } from '../../playwright/attributes';
import type {
    AttributeFieldProblem,
    FollowView,
    PreparedView,
    Platform,
    RaProfileChoice,
    RequestFailure,
    RequestFormsView,
    RequestOffers,
} from '../bridge';
import { strings } from '../strings';
import { Request } from './Request';

const profile = (name: string, over: Partial<RaProfileChoice> = {}): RaProfileChoice => ({
    uuid: `ra-${name}`,
    name,
    description: `${name} description`,
    authority: 'Example CA',
    authority_uuid: 'ca-1',
    ...over,
});
const mtls = profile('User mTLS');
const signing = profile('Code signing', { description: null, authority: null });

const noForms: RequestFormsView = { request: null, issue: null, custom: null };
const subjectForm = attributeForm(
    [
        attributeField('cn', { label: 'Common name', required: true, value: { kind: 'text', value: 'Alex Morgan' } }),
        attributeField('o', { label: 'Organization', readOnly: true, value: { kind: 'text', value: 'Example Corp' } }),
    ],
    { id: 'form-request' },
);
const issueForm = attributeForm([attributeField('validity', { label: 'Validity' })], { id: 'form-issue' });
const customForm = attributeForm([attributeField('owner', { label: 'Owner' })], { id: 'form-custom' });

const mac: RequestOffers = {
    storages: [{ storage: 'keychain', keyTypes: ['rsa2048', 'ecP256', 'ecP384'], defaultKeyType: 'ecP256' }],
    defaultStorage: 'keychain',
};
const windows: RequestOffers = {
    storages: [
        { storage: 'software', keyTypes: ['rsa2048', 'rsa4096'], defaultKeyType: 'rsa2048' },
        { storage: 'tpm', keyTypes: ['ecP256', 'rsa2048'], defaultKeyType: 'ecP256' },
    ],
    defaultStorage: 'tpm',
};

let container: HTMLElement;
let root: Root;
let forms: RequestFormsView;
let offers: RequestOffers | 'refused';
let requested: { certificate: string; label: string } | RequestFailure | string;
let following: FollowView[];
let calls: { command: string; args: unknown }[];
let closed: number;
let checkProblems: AttributeFieldProblem[];

beforeEach(() => {
    (globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true;
    container = document.createElement('div');
    document.body.append(container);
    root = createRoot(container);
    forms = noForms;
    offers = mac;
    requested = { certificate: 'cert-1', label: 'User mTLS' };
    following = [{ state: 'unknown' }];
    calls = [];
    closed = 0;
    checkProblems = [];
    mockIPC((command, args) => {
        calls.push({ command, args });
        switch (command) {
            case 'check_attributes':
                return { revision: 0, problems: checkProblems };
            case 'open_request_forms':
            case 'open_prepared_forms':
                return forms;
            case 'request_offers':
                return offers === 'refused' ? Promise.reject('no') : offers;
            case 'request_certificate':
            case 'complete_certificate':
                return typeof requested === 'object' && 'certificate' in requested ? requested : Promise.reject(requested);
            case 'follow_request':
                return following.length > 1 ? following.shift() : following[0];
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

const render = (profiles = [mtls, signing], platform: Platform = 'macos') =>
    act(async () => root.render(<Request profiles={profiles} platform={platform} onClose={() => (closed += 1)} />));

const dialog = () => container.querySelector('dialog') as HTMLDialogElement;
const button = (name: string) => [...dialog().querySelectorAll('button')].find((candidate) => candidate.textContent === name);
const press = (name: string) => act(async () => button(name)?.click());
const text = () => dialog().textContent ?? '';
const named = (command: string) => calls.filter((call) => call.command === command);
const settle = (ms = 30) => act(async () => new Promise((resolve) => setTimeout(resolve, ms)));
const radios = () => [...dialog().querySelectorAll<HTMLInputElement>('input[type="radio"]')];
const pick = (radio: HTMLInputElement | undefined) => act(async () => radio?.click());
const select = () => dialog().querySelector('select') as HTMLSelectElement;
const disabled = (name: string) => (button(name) as HTMLButtonElement).disabled;

async function toKey(profiles = [profile('Only')], platform: Platform = 'macos') {
    await render(profiles, platform);
    await settle();
    await press(strings.continue);
}

test('the sheet is titled and lists the four steps with the current one marked', async () => {
    await render();

    expect(dialog().open).toBe(true);
    expect(dialog().querySelector('h2')?.textContent).toBe('Request a certificate');
    expect(dialog().getAttribute('aria-labelledby')).toBe(dialog().querySelector('h2')?.id);
    const steps = [...dialog().querySelectorAll('ol[aria-label="Steps"] > li')];
    expect(steps.map((step) => step.textContent)).toEqual(['1Profile', '2Attributes', '3Private key', '4Review']);
    expect(steps.map((step) => step.getAttribute('aria-current'))).toEqual(['step', null, null, null]);
});

test('step one offers a radio card per profile with description and authority, the first chosen', async () => {
    await render();

    expect(dialog().querySelector('[role="radiogroup"]')?.getAttribute('aria-label')).toBe('RA profiles');
    expect(radios().map((radio) => radio.checked)).toEqual([true, false]);
    const cards = [...dialog().querySelectorAll('label')].map((label) => label.textContent);
    expect(cards).toEqual(['User mTLSUser mTLS descriptionAuthority: Example CA', 'Code signing']);
    expect(button(strings.cancel)).toBeDefined();
});

test('with one profile the profile step is skipped and the forms open for it', async () => {
    await render([mtls]);
    await settle();

    expect(dialog().textContent).toContain(strings.fillAttributes);
    expect(named('open_request_forms').map((call) => call.args)).toEqual([{ raProfile: 'ra-User mTLS' }]);
    expect(button(strings.back)).toBeUndefined();
    await press(strings.cancel);
    expect(closed).toBe(1);
});

test('step two shows the three groups, and none for a form that is missing', async () => {
    forms = { request: subjectForm, issue: issueForm, custom: customForm };
    await render();
    await press(strings.continue);
    await settle();

    const headings = [...dialog().querySelectorAll('h3')].map((heading) => heading.textContent);
    expect(headings).toEqual([strings.fillAttributes, 'Certificate request', 'From the RA profile', 'Custom attributes']);

    await press(strings.back);
    forms = { request: subjectForm, issue: null, custom: null };
    await press(strings.continue);
    await settle();
    expect([...dialog().querySelectorAll('h3')].map((heading) => heading.textContent)).toEqual([
        strings.fillAttributes,
        'Certificate request',
    ]);
});

test('Continue waits for valid forms, and going back to the profiles closes the forms', async () => {
    forms = { request: subjectForm, issue: issueForm, custom: null };
    checkProblems = [{ name: 'validity', problem: { kind: 'required' } }];
    await render();
    await press(strings.continue);
    await settle();
    expect(disabled(strings.continue)).toBe(true);

    await press(strings.back);

    expect(named('close_form').map((call) => call.args)).toEqual([{ id: 'form-request' }, { id: 'form-issue' }]);
    expect(dialog().textContent).toContain(strings.chooseProfile);
});

test('cancelling on the attributes closes every open form', async () => {
    forms = { request: subjectForm, issue: null, custom: customForm };
    await render([mtls]);
    await settle();

    await act(async () => root.render(null));

    expect(named('close_form').map((call) => call.args)).toEqual([{ id: 'form-request' }, { id: 'form-custom' }]);
});

test('a form that opens after the sheet is gone is closed at once', async () => {
    forms = { request: subjectForm, issue: null, custom: null };
    let open: (view: RequestFormsView) => void = () => undefined;
    mockIPC((command, args) => {
        calls.push({ command, args });
        if (command === 'open_request_forms') {
            return new Promise((resolve) => {
                open = resolve;
            });
        }
    });
    await render([mtls]);
    await act(async () => root.render(null));

    await act(async () => open(forms));

    expect(named('close_form').map((call) => call.args)).toEqual([{ id: 'form-request' }]);
});

test('the forms that cannot be opened are said so and Continue stays off', async () => {
    mockIPC((command) => (command === 'open_request_forms' ? Promise.reject('no') : undefined));
    await render([mtls]);
    await settle();

    expect(dialog().querySelector('[role="alert"]')?.textContent).toBe(strings.requestFormsFailed);
    expect(disabled(strings.continue)).toBe(true);
});

test('step three says where the key lives, on this Mac, and preselects the recommended keychain with EC P-256', async () => {
    await toKey();

    expect(text()).toContain('Where should the private key live?');
    expect(text()).toContain('The key is created on this Mac and never leaves it.');
    expect(dialog().querySelector('[role="radiogroup"]')?.getAttribute('aria-label')).toBe('Key storage');
    expect(text()).toContain('KeychainIn your login keychain, marked as not exportable.Recommended');
    expect(radios()[0]?.checked).toBe(true);
    expect([...select().options].map((option) => option.textContent)).toEqual(['RSA 2048', 'EC P-256', 'EC P-384']);
    expect(select().value).toBe('ecP256');
    expect(dialog().querySelector(`label[for="${select().id}"]`)?.textContent).toBe('Key type');
});

test('step three says this PC and this computer on the other systems', async () => {
    await toKey([profile('Only')], 'windows');
    expect(text()).toContain('this PC and never leaves it');

    await act(async () => root.render(null));
    await toKey([profile('Only')], 'linux');
    expect(text()).toContain('on this computer and never leaves it');
});

test('on Windows the storages are named plainly, the default is recommended and switching storage re-picks the key type', async () => {
    offers = windows;
    await toKey([profile('Only')], 'windows');

    const cards = [...dialog().querySelectorAll('label')].filter((label) => label.querySelector('input[type="radio"]'));
    expect(cards.map((card) => card.textContent)).toEqual([
        'Windows key storeIn your user profile, marked as not exportable.',
        'TPMProtected by the security chip in this PC. Cannot be copied.Recommended',
    ]);
    expect(radios().map((radio) => radio.checked)).toEqual([false, true]);
    expect(select().value).toBe('ecP256');

    await pick(radios()[0]);

    expect([...select().options].map((option) => option.value)).toEqual(['rsa2048', 'rsa4096']);
    expect(select().value).toBe('rsa2048');
});

test('a software storage elsewhere gets a neutral text, and a storage without EC P-256 starts with its first type', async () => {
    offers = { storages: [{ storage: 'software', keyTypes: ['mlDsa65', 'rsa3072'], defaultKeyType: 'mlDsa65' }], defaultStorage: null };
    await toKey([profile('Only')], 'linux');

    expect(text()).toContain('Software keyKept on this computer for your user account only.');
    expect(select().value).toBe('mlDsa65');
    expect([...select().options].map((option) => option.textContent)).toEqual(['ML-DSA-65', 'RSA 3072']);
});

test('the other key types are named readably', async () => {
    offers = {
        storages: [{ storage: 'keychain', keyTypes: ['ecP521', 'rsa3072', 'rsa4096', 'mlDsa44', 'mlDsa87'], defaultKeyType: 'ecP521' }],
        defaultStorage: 'keychain',
    };
    await toKey();

    expect([...select().options].map((option) => option.textContent)).toEqual([
        'EC P-521',
        'RSA 3072',
        'RSA 4096',
        'ML-DSA-44',
        'ML-DSA-87',
    ]);
});

test('without a storage nothing can be chosen and Continue is off', async () => {
    offers = { storages: [], defaultStorage: null };
    await toKey();

    expect(text()).toContain('Your organization does not allow a key storage on this computer.');
    expect(radios()).toHaveLength(0);
    expect(disabled(strings.continue)).toBe(true);
});

test('storages that cannot be read are said so', async () => {
    offers = 'refused';
    await toKey();

    expect(dialog().querySelector('[role="alert"]')?.textContent).toBe(strings.offersFailed);
    expect(disabled(strings.continue)).toBe(true);
});

test('the key step is reached with Back to the attributes and keeps what was typed', async () => {
    forms = { request: subjectForm, issue: null, custom: null };
    await render([mtls]);
    await settle();
    await press(strings.continue);
    await press(strings.back);

    expect(dialog().querySelector('input[type="text"]')).not.toBeNull();
    expect((dialog().querySelector('input[type="text"]') as HTMLInputElement).value).toBe('Alex Morgan');
});

async function toReview(platform: Platform = 'macos') {
    forms = { request: subjectForm, issue: null, custom: null };
    await render([mtls], platform);
    await settle();
    await press(strings.continue);
    await settle();
    await press(strings.continue);
}

test('the review lists profile, subject, key and where it is installed, with the three lines', async () => {
    await toReview();

    const rows = [...dialog().querySelectorAll('dl > div')].map((row) => row.textContent);
    expect(rows).toEqual([
        'ProfileUser mTLS',
        'SubjectAlex Morgan, Example Corp',
        'Private keyNew, in the keychain',
        'Key typeEC P-256',
        'Installed inYour login keychain',
    ]);
    expect([...dialog().querySelectorAll('ol[aria-label="What happens next"] li')].map((item) => item.textContent)).toEqual([
        '1A new key is created in the keychain.',
        '2A request signed with that key goes to ILM. The key itself is never sent.',
        '3ILM issues the certificate and this app installs it with its intermediates.',
    ]);
    expect(button('Request certificate')).toBeDefined();
});

test('on Windows the review names the TPM and the personal certificate store, with the confirming button first', async () => {
    offers = windows;
    await toReview('windows');

    expect(text()).toContain('New, in the TPM');
    expect(text()).toContain('Your personal certificate store');
    expect([...dialog().querySelectorAll('button')].map((candidate) => candidate.textContent)).toEqual(['Request certificate', 'Back']);
});

test('the review names a Windows key store and software elsewhere', async () => {
    offers = { storages: [{ storage: 'software', keyTypes: ['rsa2048'], defaultKeyType: 'rsa2048' }], defaultStorage: 'software' };
    await toReview('windows');
    expect(text()).toContain('New, in the Windows key store');

    await act(async () => root.render(null));
    await toReview('linux');
    expect(text()).toContain('New, in software');
});

test('the subject shows the label of a chosen option', async () => {
    forms = {
        request: attributeForm(
            [
                attributeField('c', {
                    label: 'Country',
                    kind: 'select',
                    options: [{ key: 'cz', label: 'Czechia' }],
                    value: { kind: 'option', value: 'cz' },
                }),
                attributeField('i', { label: 'Note', kind: 'info', value: { kind: 'text', value: 'Hello' } }),
            ],
            { id: 'form-request' },
        ),
        issue: null,
        custom: null,
    };
    await render([mtls]);
    await settle();
    await press(strings.continue);
    await settle();
    await press(strings.continue);

    expect(text()).toContain('SubjectCzechia');
});

test('Request certificate sends the profile, the forms by id, the storage and the key type, then shows the end', async () => {
    forms = { request: subjectForm, issue: null, custom: customForm };
    vi.useFakeTimers({ toFake: ['setTimeout', 'clearTimeout'] });
    await render([mtls]);
    await act(async () => vi.advanceTimersByTimeAsync(400));
    await press(strings.continue);
    await act(async () => vi.advanceTimersByTimeAsync(400));
    await press(strings.continue);
    following = [{ state: 'installed', storage: 'keychain', validUntil: new Date(2027, 10, 10).getTime() }];

    await press('Request certificate');

    expect(named('request_certificate')[0]?.args).toEqual({
        raProfile: 'ra-User mTLS',
        forms: {
            request: {
                id: 'form-request',
                values: { cn: { kind: 'text', value: 'Alex Morgan' }, o: { kind: 'text', value: 'Example Corp' } },
            },
            custom: { id: 'form-custom', values: {} },
        },
        storage: 'keychain',
        keyType: 'ecP256',
    });
    expect(named('close_form')).toHaveLength(0);
    expect(dialog().querySelector('ol[aria-label="Steps"]')).toBeNull();
    expect(text()).toContain('Your certificate is installed');
    expect(text()).toContain('User mTLS is in your login keychain.');
    expect([...dialog().querySelectorAll('dl > div')].map((row) => row.textContent)).toEqual([
        `Valid until${strings.date(new Date(2027, 10, 10).getTime())}`,
        'Private keyKeychain',
    ]);
    expect(button('Done')).toBeDefined();
    await press('Done');
    expect(closed).toBe(1);
});

async function request() {
    vi.useFakeTimers({ toFake: ['setTimeout', 'clearTimeout'] });
    await render([mtls], 'windows');
    await act(async () => vi.advanceTimersByTimeAsync(400));
    await press(strings.continue);
    await press(strings.continue);
    await press('Request certificate');
}

test('on Windows the installed end says the personal certificate store', async () => {
    offers = windows;
    following = [{ state: 'installed', storage: 'tpm', validUntil: 0 }];
    await request();

    expect(text()).toContain('User mTLS is in your personal certificate store.');
    expect(text()).toContain('Private keyTPM');
});

test('a request still waiting is followed every two seconds and the sheet says so', async () => {
    following = [{ state: 'waiting', stage: 'pendingApproval' }];
    await request();

    expect(text()).toContain('Waiting for approval');
    expect(text()).toContain('The app installs it when ILM issues it. You can close this window.');
    expect(named('follow_request')).toHaveLength(1);
    expect(named('follow_request')[0]?.args).toEqual({ certificate: 'cert-1' });

    await act(async () => vi.advanceTimersByTimeAsync(2000));
    expect(named('follow_request')).toHaveLength(2);

    following = [{ state: 'waiting', stage: 'beingIssued' }];
    await act(async () => vi.advanceTimersByTimeAsync(2000));
    expect(text()).toContain('ILM is issuing your certificate');
    expect(button('Done')).toBeDefined();
});

test('an unknown standing reads as issuing, and the following ends after sixty seconds', async () => {
    following = [{ state: 'unknown' }];
    await request();

    expect(text()).toContain('ILM is issuing your certificate');
    await act(async () => vi.advanceTimersByTimeAsync(120000));
    expect(named('follow_request')).toHaveLength(30);
    expect(named('stop_following_request')).toHaveLength(1);
});

test('a certificate issued but not installed is released to the notices while the app tries again', async () => {
    following = [{ state: 'notInstalled', cause: 'installFailed' }];
    await request();

    expect(named('stop_following_request')).toHaveLength(1);
});

test('a request that is over stays with the wizard until it closes', async () => {
    following = [{ state: 'ended', reason: 'rejected' }];
    await request();

    expect(named('stop_following_request')).toHaveLength(0);
});

test('a failing follow is tried again', async () => {
    let fail = true;
    mockIPC((command, args) => {
        calls.push({ command, args });
        if (command === 'request_certificate') {
            return requested;
        }
        if (command === 'request_offers') {
            return mac;
        }
        if (command === 'follow_request') {
            return fail ? Promise.reject('no') : { state: 'waiting', stage: 'beingIssued' };
        }
        return noForms;
    });
    await request();
    fail = false;

    await act(async () => vi.advanceTimersByTimeAsync(2000));

    expect(text()).toContain('ILM is issuing your certificate');
});

test('closing the sheet stops the following', async () => {
    following = [{ state: 'waiting', stage: 'pendingApproval' }];
    await request();

    await act(async () => root.render(null));
    await act(async () => vi.advanceTimersByTimeAsync(10000));

    expect(named('follow_request')).toHaveLength(1);
});

test('closing the sheet tells the app it no longer shows the request', async () => {
    following = [{ state: 'waiting', stage: 'pendingApproval' }];
    await request();
    expect(named('stop_following_request')).toHaveLength(0);

    await act(async () => root.render(null));

    expect(named('stop_following_request')).toHaveLength(1);
    expect(named('stop_following_request')[0]?.args).toEqual({ certificate: 'cert-1' });
});

test('a request that ILM takes after the sheet is gone is left to the notices', async () => {
    let finish: (value: unknown) => void = () => undefined;
    mockIPC((command, args) => {
        calls.push({ command, args });
        if (command === 'request_certificate') {
            return new Promise((resolve) => {
                finish = resolve;
            });
        }
        return command === 'request_offers' ? mac : noForms;
    });
    await request();
    await act(async () => root.render(null));

    await act(async () => finish(requested));

    expect(named('follow_request')).toHaveLength(0);
    expect(named('stop_following_request').map((call) => call.args)).toEqual([{ certificate: 'cert-1' }]);
});

test('the forms of a request that fails after the sheet is gone are closed', async () => {
    forms = { request: subjectForm, issue: null, custom: customForm };
    let fail: (reason: unknown) => void = () => undefined;
    mockIPC((command, args) => {
        calls.push({ command, args });
        switch (command) {
            case 'check_attributes':
                return { revision: 0, problems: [] };
            case 'open_request_forms':
                return forms;
            case 'request_offers':
                return mac;
            case 'request_certificate':
                return new Promise((_, reject) => {
                    fail = reject;
                });
            default:
                return undefined;
        }
    });
    vi.useFakeTimers({ toFake: ['setTimeout', 'clearTimeout'] });
    await render([mtls]);
    await act(async () => vi.advanceTimersByTimeAsync(400));
    await press(strings.continue);
    await act(async () => vi.advanceTimersByTimeAsync(400));
    await press(strings.continue);
    await press('Request certificate');
    await act(async () => root.render(null));
    const before = named('close_form').length;

    await act(async () => fail({ kind: 'message', message: 'ILM is not reachable.' }));

    expect(
        named('close_form')
            .slice(before)
            .map((call) => call.args),
    ).toEqual([{ id: 'form-request' }, { id: 'form-custom' }]);
});

test('a sheet closed before a request was made does not tell the app anything', async () => {
    await render();
    await act(async () => root.render(null));

    expect(named('stop_following_request')).toHaveLength(0);
});

test('the end of a request ILM turned down or could not issue is said in plain words', async () => {
    following = [{ state: 'ended', reason: 'rejected' }];
    await request();
    expect(text()).toContain('ILM rejected the request.');
    expect(named('follow_request')).toHaveLength(1);

    await act(async () => root.render(null));
    calls = [];
    following = [{ state: 'ended', reason: 'failed' }];
    await request();
    expect(text()).toContain('ILM could not issue the certificate.');
});

test('a certificate issued but not installed says why', async () => {
    following = [{ state: 'notInstalled', cause: 'installFailed' }];
    await request();
    expect(text()).toContain('ILM issued the certificate, but it could not be installed. The app will try again.');

    await act(async () => root.render(null));
    following = [{ state: 'notInstalled', cause: 'otherKey' }];
    await request();
    expect(text()).toContain('does not match the key created for this request');
});

test('a request ILM refused with messages goes back to the attributes with them as they are', async () => {
    forms = { request: subjectForm, issue: null, custom: null };
    requested = { kind: 'refused', messages: ['Common name is required.', 'Another reason.'] };
    vi.useFakeTimers({ toFake: ['setTimeout', 'clearTimeout'] });
    await render([mtls]);
    await act(async () => vi.advanceTimersByTimeAsync(400));
    await press(strings.continue);
    await act(async () => vi.advanceTimersByTimeAsync(400));
    await press(strings.continue);

    await press('Request certificate');

    expect(dialog().textContent).toContain(strings.fillAttributes);
    const alert = dialog().querySelector('[role="alert"]');
    expect(alert?.textContent).toBe('ILM did not accept the requestCommon name is required.Another reason.');
    expect(dialog().querySelector('li[aria-current="step"]')?.textContent).toBe('2Attributes');
    expect(named('close_form')).toHaveLength(0);
});

test('field problems go to the fields and the alert says some need attention', async () => {
    forms = { request: subjectForm, issue: null, custom: null };
    requested = { kind: 'problems', problems: [{ name: 'cn', problem: { kind: 'required' } }] };
    vi.useFakeTimers({ toFake: ['setTimeout', 'clearTimeout'] });
    await render([mtls]);
    await act(async () => vi.advanceTimersByTimeAsync(400));
    await press(strings.continue);
    await act(async () => vi.advanceTimersByTimeAsync(400));
    await press(strings.continue);

    await press('Request certificate');

    expect(dialog().querySelector('[role="alert"]')?.textContent).toContain(strings.requestRefused);
    expect(dialog().querySelector('[role="alert"]')?.textContent).toContain(strings.attributesNeedAttention);
    expect(text()).toContain('Enter a value.');
});

test('another failure is shown on the review step and the request can be repeated', async () => {
    requested = { kind: 'message', message: 'ILM is not reachable.' };
    await request();

    expect(dialog().querySelector('[role="alert"]')?.textContent).toBe('ILM is not reachable.');
    expect(dialog().querySelector('li[aria-current="step"]')?.textContent).toBe('4Review');
    expect(button('Request certificate')).toBeDefined();
});

test('an unexpected rejection is shown, and one without words gets a plain message', async () => {
    requested = 'Something broke.';
    await request();
    expect(dialog().querySelector('[role="alert"]')?.textContent).toBe('Something broke.');

    await act(async () => root.render(null));
    requested = '';
    await request();
    expect(dialog().querySelector('[role="alert"]')?.textContent).toBe(strings.requestFailed);
});

test('while the request is made the button says so and the sheet cannot be dismissed', async () => {
    let finish: (value: unknown) => void = () => undefined;
    mockIPC((command, args) => {
        calls.push({ command, args });
        if (command === 'request_certificate') {
            return new Promise((resolve) => {
                finish = resolve;
            });
        }
        if (command === 'request_offers') {
            return mac;
        }
        return command === 'open_request_forms' ? noForms : { state: 'unknown' };
    });
    await request();

    expect(button('Requesting…')).toBeDefined();
    expect((button('Requesting…') as HTMLButtonElement).disabled).toBe(true);
    expect(disabled(strings.back)).toBe(true);
    await act(async () => {
        dialog().dispatchEvent(new Event('cancel', { cancelable: true }));
    });
    expect(closed).toBe(0);

    await act(async () => finish({ certificate: 'cert-1', label: 'User mTLS' }));
    expect(text()).toContain('ILM is issuing your certificate');
});

test('Escape closes the sheet before the request is made', async () => {
    await render();

    await act(async () => {
        dialog().dispatchEvent(new Event('cancel', { cancelable: true }));
    });

    expect(closed).toBe(1);
});

test('the profile cards are one radio group that the arrow keys walk', async () => {
    await render();

    expect(new Set(radios().map((radio) => radio.name)).size).toBe(1);
    await pick(radios()[1]);
    expect(radios().map((radio) => radio.checked)).toEqual([false, true]);
    await press(strings.continue);
    expect(named('open_request_forms')[0]?.args).toEqual({ raProfile: 'ra-Code signing' });
});

const readyToIssue = (over: Partial<PreparedView> = {}): PreparedView => ({
    uuid: 'prep-1',
    name: 'VPN gateway access',
    raProfile: { uuid: 'ra-vpn', name: 'Corporate VPN' },
    registration: { state: 'active', expiresAt: null },
    subject: [
        { kind: 'commonName', value: 'vpn-alice', oid: null },
        { kind: 'organization', value: 'Example Corp', oid: null },
        { kind: 'other', value: 'LT-1', oid: '1.2.3.4' },
        { kind: 'email', value: 'alice@example.com', oid: null },
        { kind: 'dns', value: 'alice.example.com', oid: null },
    ],
    ...over,
});

const renderPrepared = async (prepared = readyToIssue(), platform: Platform = 'macos') => {
    await act(async () => root.render(<Request prepared={prepared} platform={platform} onClose={() => (closed += 1)} />));
    await settle();
};
const field = () => dialog().querySelector('input[type="password"]') as HTMLInputElement | null;
const type = (input: HTMLInputElement, value: string) =>
    act(async () => {
        const set = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value')?.set;
        set?.call(input, value);
        input.dispatchEvent(new Event('input', { bubbles: true }));
    });
async function preparedToReview(prepared = readyToIssue()) {
    await renderPrepared(prepared);
    await press(strings.continue);
    await press(strings.continue);
}

test('a prepared certificate is issued in three steps, titled with its name, with no profile step', async () => {
    forms = { request: null, issue: issueForm, custom: customForm };
    await renderPrepared();

    expect(dialog().querySelector('h2')?.textContent).toBe('Issue VPN gateway access');
    expect([...dialog().querySelectorAll('ol[aria-label="Steps"] > li')].map((step) => step.textContent)).toEqual([
        '1Attributes',
        '2Private key',
        '3Review',
    ]);
    expect(named('open_prepared_forms').map((call) => call.args)).toEqual([{ uuid: 'prep-1' }]);
    expect(named('open_request_forms')).toHaveLength(0);
    expect([...dialog().querySelectorAll('h3')].map((heading) => heading.textContent)).toEqual([
        strings.fillAttributes,
        'Prepared by your administrator',
        'From the RA profile',
        'Custom attributes',
    ]);
    expect([...dialog().querySelectorAll('section dl > div')].map((row) => row.textContent)).toEqual([
        'Namevpn-alice',
        'OrganizationExample Corp',
        '1.2.3.4LT-1',
        'Email in the certificatealice@example.com',
        'DNS namealice.example.com',
        'RA profileCorporate VPN',
    ]);
    expect([...dialog().querySelectorAll('button')].map((candidate) => candidate.textContent)).toEqual(['Cancel', 'Continue']);
});

test.each([
    ['commonName', 'Name'],
    ['organization', 'Organization'],
    ['organizationalUnit', 'Organizational unit'],
    ['country', 'Country'],
    ['state', 'State or province'],
    ['locality', 'Locality'],
    ['email', 'Email in the certificate'],
    ['serialNumber', 'Serial number'],
    ['domainComponent', 'Domain component'],
    ['other', 'Other'],
    ['dns', 'DNS name'],
    ['ip', 'IP address'],
    ['uri', 'URI'],
    ['upn', 'User principal name'],
] as const)('a prepared %s is labelled "%s"', async (kind, label) => {
    await renderPrepared(readyToIssue({ subject: [{ kind, value: 'v', oid: null }] }));

    expect(dialog().querySelector('section dl > div')?.textContent).toBe(`${label}v`);
});

test('cancelling a prepared certificate closes its forms and the sheet', async () => {
    forms = { request: null, issue: issueForm, custom: customForm };
    await renderPrepared();
    await press(strings.cancel);
    expect(closed).toBe(1);

    await act(async () => root.render(null));

    expect(named('close_form').map((call) => call.args)).toEqual([{ id: 'form-issue' }, { id: 'form-custom' }]);
});

test('the review of a prepared certificate lists its name, subject and RA profile, and has the challenge field when active', async () => {
    await preparedToReview();

    expect([...([...dialog().querySelectorAll('dl')].at(-1) as HTMLElement).children].map((row) => row.textContent)).toEqual([
        'CertificateVPN gateway access',
        'Subjectvpn-alice, Example Corp, LT-1',
        'RA profileCorporate VPN',
        'Private keyNew, in the keychain',
        'Key typeEC P-256',
        'Installed inYour login keychain',
    ]);
    expect(dialog().querySelector(`label[for="${field()?.id}"]`)?.textContent).toBe('Challenge');
    expect(text()).toContain('Your administrator gives you this with the certificate.');
    expect(disabled('Issue certificate')).toBe(true);
    expect(button('Request certificate')).toBeUndefined();
});

test('an email in the registered name is part of the reviewed subject, one among the alternative names is not', async () => {
    await preparedToReview(
        readyToIssue({
            subject: [
                { kind: 'commonName', value: 'vpn-alice', oid: null },
                { kind: 'email', value: 'alice@example.com', oid: '1.2.840.113549.1.9.1' },
                { kind: 'email', value: 'other@example.com', oid: null },
            ],
        }),
    );

    expect(text()).toContain('Subjectvpn-alice, alice@example.com');
    expect(text()).not.toContain('alice@example.com, other@example.com');
});

test.each([['closed'], ['other']])('a prepared certificate in state %s has no challenge field', async (state) => {
    await preparedToReview(readyToIssue({ registration: { state, expiresAt: null } }));

    expect(field()).toBeNull();
    expect(disabled('Issue certificate')).toBe(false);
});

test('without a registration nothing asks for a challenge and none is sent', async () => {
    await preparedToReview(readyToIssue({ registration: null }));

    await press('Issue certificate');

    expect(named('complete_certificate')[0]?.args).toEqual({
        uuid: 'prep-1',
        forms: {},
        storage: 'keychain',
        keyType: 'ecP256',
        challenge: null,
        subject: readyToIssue().subject,
    });
});

test('Issue certificate waits for the challenge and sends it with the forms, then shows the end', async () => {
    forms = { request: null, issue: issueForm, custom: null };
    following = [{ state: 'installed', storage: 'keychain', validUntil: 0 }];
    await preparedToReview();
    await type(field() as HTMLInputElement, 'secret-1');
    expect(disabled('Issue certificate')).toBe(false);

    await press('Issue certificate');

    expect(named('complete_certificate')[0]?.args).toEqual({
        uuid: 'prep-1',
        forms: { issue: { id: 'form-issue', values: {} } },
        storage: 'keychain',
        keyType: 'ecP256',
        challenge: 'secret-1',
        subject: readyToIssue().subject,
    });
    expect(named('request_certificate')).toHaveLength(0);
    expect(text()).toContain('Your certificate is installed');
    expect(field()).toBeNull();
});

test('a refusal with ILM’s challenge texts stays on the review, under the field, which is cleared and focused', async () => {
    const texts = ['The certificate registration challenge is invalid.', 'The certificate registration issuance window has expired.'];
    requested = { kind: 'refused', messages: texts };
    await preparedToReview();
    await type(field() as HTMLInputElement, 'wrong');

    await press('Issue certificate');

    const input = field() as HTMLInputElement;
    expect(dialog().querySelector('[aria-current="step"]')?.textContent).toBe('3Review');
    expect(input.value).toBe('');
    expect(document.activeElement).toBe(input);
    expect(input.getAttribute('aria-invalid')).toBe('true');
    const problem = dialog().querySelector(`#${CSS.escape(input.getAttribute('aria-describedby')?.split(' ')[1] ?? '')}`);
    expect(problem?.textContent).toBe(texts.join(''));
    expect(disabled('Issue certificate')).toBe(true);

    await type(input, 'x');
    expect(input.getAttribute('aria-invalid')).toBeNull();
    expect(dialog().querySelector('[role="alert"]')).toBeNull();
});

test('any other refusal of a prepared certificate goes back to the attributes with ILM’s messages', async () => {
    requested = {
        kind: 'refused',
        messages: ['The certificate registration challenge is invalid.', 'Something else is wrong.'],
    };
    await preparedToReview();
    await type(field() as HTMLInputElement, 'wrong');

    await press('Issue certificate');

    expect(dialog().querySelector('[aria-current="step"]')?.textContent).toBe('1Attributes');
    expect(dialog().querySelector('[role="alert"]')?.textContent).toContain('Something else is wrong.');
});

test('a challenge asked for among other refusals opens the field for the next send', async () => {
    requested = {
        kind: 'refused',
        messages: ['The certificate registration challenge is required.', 'Something else is wrong.'],
    };
    await preparedToReview(readyToIssue({ registration: null }));

    await press('Issue certificate');
    await press('Continue');
    await press('Continue');

    expect(dialog().querySelector('[aria-current="step"]')?.textContent).toBe('3Review');
    expect(field()).not.toBeNull();
});

test('a failure with a message stays on the review and says it', async () => {
    requested = 'ILM does not allow this.';
    await preparedToReview();
    await type(field() as HTMLInputElement, 'x');

    await press('Issue certificate');

    expect(dialog().querySelector('[role="alert"]')?.textContent).toBe('ILM does not allow this.');
    expect((field() as HTMLInputElement).value).toBe('');
});

test('ILM asking for a challenge the registration did not show opens the field with its text', async () => {
    requested = { kind: 'refused', messages: ['The certificate registration challenge is required.'] };
    await preparedToReview(readyToIssue({ registration: null }));

    await press('Issue certificate');

    const input = field() as HTMLInputElement;
    expect(dialog().querySelector('[aria-current="step"]')?.textContent).toBe('3Review');
    expect(dialog().querySelector('[role="alert"]')?.textContent).toBe('The certificate registration challenge is required.');
    await type(input, 'secret-2');
    expect(field()).toBe(input);
    await press('Issue certificate');
    expect(named('complete_certificate')[1]?.args).toMatchObject({ challenge: 'secret-2' });
});
