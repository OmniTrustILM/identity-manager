import type { AttentionItemView, IlmCertificateView, IlmPageView, InventoryView, LocalCertificateView, SummaryView } from '../src/bridge';

const day = 24 * 60 * 60 * 1000;

/** A certificate in ILM, issued and valid, with the dates relative to now. */
export const ilmCertificate = (name: string, over: Partial<IlmCertificateView> = {}): IlmCertificateView => ({
    uuid: `uuid-${name}`,
    name,
    subjectDn: `CN=${name}`,
    issuerName: 'Demo Client Sub CA',
    serial: '5E:2B:9A:01',
    notBefore: Date.now() - 100 * day,
    notAfter: Date.now() + 212 * day,
    fingerprint: `IL:${name}`,
    key: 'RSA 2048',
    state: 'issued',
    validationStatus: 'valid',
    raProfile: null,
    owner: 'alex.morgan',
    groups: [],
    archived: false,
    ...over,
});

export const page = (certificates: IlmCertificateView[], over: Partial<IlmPageView> = {}): IlmPageView => ({
    certificates,
    pageNumber: 1,
    totalPages: 1,
    totalItems: certificates.length,
    ...over,
});

const checkedAt = new Date(2026, 5, 21, 10, 38).getTime();

/** What the application knows after a check that worked; `matches` are keyed by the local fingerprint. */
export const inventory = (over: Partial<InventoryView> = {}): InventoryView => ({
    status: { state: 'fresh', checkedAt },
    checking: false,
    checkedAt,
    listed: true,
    checked: Object.keys(over.matches ?? {}),
    matches: {},
    signIn: null,
    firstPage: null,
    canRequest: false,
    ...over,
});

/** A certificate of this computer, valid, with the dates relative to now. */
export const localCertificate = (name: string, over: Partial<LocalCertificateView> = {}): LocalCertificateView => ({
    fingerprint: `LO:${name}`,
    name,
    subject: `CN=${name},O=Demo Org`,
    issuer: 'CN=Demo Issuing CA',
    issuerName: 'Demo Issuing CA',
    serial: '7A:10:C5:3B',
    notBefore: Date.now() - 100 * day,
    notAfter: Date.now() + 212 * day,
    uses: [{ kind: 'clientAuth' }],
    alternativeNames: [],
    key: { kind: 'ec', value: { curve: 'P-256' } },
    location: 'keychain',
    canSignIn: true,
    signInProblem: null,
    cardName: null,
    ...over,
});

/** The items of the summary for the certificates `attentionCertificates` names, dated relative to now. */
export const attentionItems: Record<'revoked' | 'expired' | 'expiring' | 'later', AttentionItemView> = {
    revoked: { kind: 'revoked', fingerprint: 'LO:Build server', name: 'Build server' },
    expired: { kind: 'expired', fingerprint: 'LO:Smart card login', name: 'Smart card login', on: Date.now() - 6 * day },
    expiring: { kind: 'expiring', fingerprint: 'LO:vpn.example.com', name: 'vpn.example.com', days: 13, on: Date.now() + 13 * day },
    later: { kind: 'expiring', fingerprint: 'LO:Alex Novak', name: 'Alex Novak', days: 29, on: Date.now() + 29 * day },
};

/** The certificates of this computer that `attentionItems` is about, and three that ILM does not know. */
export const attentionCertificates = [
    localCertificate('Build server'),
    localCertificate('Smart card login', { notAfter: Date.now() - 6 * day }),
    localCertificate('vpn.example.com', { notAfter: Date.now() + 13 * day }),
    localCertificate('Alex Novak', { notAfter: Date.now() + 29 * day }),
    localCertificate('wifi-corp', { issuerName: 'Example Issuing CA 2' }),
    localCertificate('vpn-client', { issuerName: 'Example Lab Root' }),
    localCertificate('Lab device'),
];

/** How the certificates stand, computed now; `months` runs from the current month. */
export const summary = (attention: AttentionItemView[], over: Partial<SummaryView> = {}): SummaryView => ({
    computedAt: Date.now(),
    checkedAt,
    listed: true,
    counts: { valid: 3, expiring: 2, expired: 2, notInIlm: 3 },
    attention,
    months: [0, 2, 0, 1, 0, 1, 0, 1, 0, 2, 0, 1],
    ...over,
});

/** The inventory that goes with `attentionCertificates`: the first four are in ILM, the last three are not. */
export const attentionInventory = (over: Partial<InventoryView> = {}): InventoryView =>
    inventory({
        checked: attentionCertificates.map((certificate) => certificate.fingerprint),
        matches: Object.fromEntries(
            attentionCertificates.slice(0, 4).map((certificate) => [certificate.fingerprint, ilmCertificate(certificate.name)]),
        ),
        ...over,
    });
