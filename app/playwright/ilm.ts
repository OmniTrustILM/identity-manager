import type { IlmCertificateView, IlmPageView, InventoryView } from '../src/bridge';

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
    matches: {},
    signIn: null,
    firstPage: null,
    ...over,
});
