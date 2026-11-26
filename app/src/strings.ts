import type { AutomaticRenewal } from './bridge/generated/AutomaticRenewal';
import type { AttributeConstraintView } from './bridge/generated/AttributeConstraintView';
import type { AttributeFieldKind } from './bridge/generated/AttributeFieldKind';
import type { AttributeProblem } from './bridge/generated/AttributeProblem';
import type { Platform } from './bridge/generated/Platform';
import type { SubjectKind } from './bridge/generated/SubjectKind';

const time = (at: number) => {
    const when = new Date(at);
    const today = when.toDateString() === new Date().toDateString();
    return new Intl.DateTimeFormat(undefined, today ? { timeStyle: 'short' } : { dateStyle: 'medium', timeStyle: 'short' }).format(when);
};

/** When a certificate expires, given its date and the calendar days left. */
const when = (date: string, days: number) => {
    if (days === 0) {
        return `today, ${date}`;
    }
    return days === 1 ? `tomorrow, ${date}` : `on ${date}, in ${days} days`;
};

const mebibytes = (bytes: number) => `${Math.round((bytes / (1024 * 1024)) * 10) / 10} MiB`;

const required: Partial<Record<AttributeFieldKind, string>> = {
    select: 'Choose a value.',
    multiselect: 'Choose at least one value.',
    date: 'Choose a date.',
    time: 'Choose a time.',
    datetime: 'Choose a date and time.',
    file: 'Choose a file.',
    code: 'Enter a script.',
    json: 'Enter JSON.',
};

/** What is wrong with a field, in words; ILM's own text for the failed rule wins when it gave one. */
const attributeProblem = (problem: AttributeProblem, kind: AttributeFieldKind | null): string => {
    switch (problem.kind) {
        case 'required':
            return (kind && required[kind]) || 'Enter a value.';
        case 'notInteger':
            return 'Enter a whole number.';
        case 'notNumber':
            return 'Enter a number.';
        case 'pattern':
            return problem.message || 'Use the format ILM expects.';
        case 'below':
            return problem.message || `Use ${problem.min} or more.`;
        case 'above':
            return problem.message || `Use ${problem.max} or less.`;
        case 'before':
            return `Use ${problem.from} or later.`;
        case 'after':
            return `Use ${problem.to} or earlier.`;
        case 'badDate':
            return 'Choose a valid date.';
        case 'badTime':
            return 'Choose a valid time.';
        case 'badDateTime':
            return 'Choose a valid date and time.';
        case 'badJson':
            return 'Enter valid JSON.';
        case 'badFile':
            return 'Choose the file again.';
        case 'fileTooLarge':
            return `Choose a file of at most ${mebibytes(problem.max)}.`;
        default:
            return 'Choose one of the listed values.';
    }
};

/** What the definition asks of a value, as a line under the field. */
const attributeConstraint = (constraint: AttributeConstraintView): string | null => {
    switch (constraint.kind) {
        case 'pattern':
            return constraint.description;
        case 'range':
            if (constraint.min !== null && constraint.max !== null) {
                return `From ${constraint.min} to ${constraint.max}`;
            }
            if (constraint.min !== null) {
                return `At least ${constraint.min}`;
            }
            return constraint.max !== null ? `At most ${constraint.max}` : null;
        default:
            if (constraint.from && constraint.to) {
                return `From ${constraint.from} to ${constraint.to}`;
            }
            if (constraint.from) {
                return `From ${constraint.from}`;
            }
            return constraint.to ? `Until ${constraint.to}` : null;
    }
};

const fileSize = (bytes: number) => {
    if (bytes < 1024) {
        return `${bytes} B`;
    }
    return bytes < 1024 * 1024 ? `${(bytes / 1024).toFixed(1)} KB` : `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
};

export const strings = {
    navigation: 'Sections',
    overview: 'Overview',
    certificates: 'Certificates',
    certificatesOnThisComputer: (count: number, platform: 'macos' | 'windows') => `${count} on this ${platform === 'macos' ? 'Mac' : 'PC'}`,
    certificatesInIlm: (count: number, inIlm: number, platform: 'macos' | 'windows') =>
        `${count} on this ${platform === 'macos' ? 'Mac' : 'PC'}, ${inIlm} of them in ILM`,
    certificatesListLabel: 'Certificates on this computer',
    certificateHeader: 'Certificate',
    privateKeyHeader: 'Private key',
    statusHeader: 'Status',
    noLocalCertificates: (platform: 'macos' | 'windows') =>
        `No certificates with a private key on this ${platform === 'macos' ? 'Mac' : 'PC'}.`,
    certificatesLoadFailed: 'The certificates could not be read.',
    tryAgain: 'Try again',
    anyPurpose: 'Any purpose',
    useLabels: {
        clientAuth: 'Client authentication',
        serverAuth: 'Server authentication',
        codeSigning: 'Code signing',
        emailProtection: 'Email protection',
        timeStamping: 'Time stamping',
        ocspSigning: 'OCSP signing',
        any: 'Any purpose',
    },
    smartCardNamed: (cardName: string) => `Smart card · ${cardName}`,
    locationLabels: {
        keychain: 'Keychain',
        smartCard: 'Smart card',
        secureEnclave: 'Secure Enclave',
        software: 'Software',
        tpm: 'TPM',
        unknown: 'Certificate store',
    },
    expiresInDays: (days: number) => `Expires in ${days} days`,
    expiresToday: 'Expires today',
    expiresTomorrow: 'Expires tomorrow',
    expiredOn: (date: string) => `Expired ${date}`,
    validFromDate: (date: string) => `Valid from ${date}`,
    date: (time: number) => new Intl.DateTimeFormat(undefined, { dateStyle: 'medium' }).format(new Date(time)),
    validFrom: 'Valid from',
    validUntil: 'Until',
    issuer: 'Issuer',
    serial: 'Serial',
    certificateGroupTitle: 'Certificate',
    useGroupTitle: 'Use',
    allowedFor: 'Allowed for',
    signInRow: 'Sign in',
    canSignInToIlm: 'Can sign in to ILM',
    signInProblems: {
        'is not for client authentication': 'Not for client authentication',
        'has expired': 'Expired',
        'is not valid yet': 'Not valid yet',
        'cannot be parsed': 'Cannot be read',
        'has a key that cannot be used without asking': 'Its key cannot be used without asking',
    } as Record<string, string>,
    otherSignInProblem: (problem: string) => `This certificate ${problem}`,
    privateKeyGroupTitle: 'Private key',
    location: 'Location',
    algorithm: 'Algorithm',
    namesGroupTitle: 'Names',
    subject: 'Subject',
    alternativeNames: 'Alternative names',
    viewLabel: 'Certificates to show',
    onThisComputer: (platform: 'macos' | 'windows') => `On this ${platform === 'macos' ? 'Mac' : 'PC'}`,
    inIlm: 'In ILM',
    managedByIlm: 'Managed by ILM',
    notInIlm: 'Not in ILM',
    managedThrough: (profile: string) => `Managed by ILM through ${profile}`,
    inIlmNotManaged: 'In ILM, not managed',
    notManaged: 'Not managed',
    signInCertificate: 'Sign-in certificate',
    yourSignInCertificate: 'Your sign-in certificate',
    inIlmGroupTitle: 'In ILM',
    stateRow: 'State',
    validationRow: 'Validation',
    managementRow: 'Management',
    raProfileRow: 'RA Profile',
    ownerRow: 'Owner',
    groupsRow: 'Groups',
    archived: 'Archived',
    checkedWithIlm: (at: number) => `Checked with ILM at ${time(at)}`,
    checkingIlm: 'Checking ILM…',
    cannotReachIlm: 'Cannot reach ILM.',
    cannotReachIlmSince: (at: number) => `Cannot reach ILM. Shown as of ${time(at)}.`,
    time,
    syncNow: 'Sync now',
    makeSignInCertificate: 'Make this my sign-in certificate',
    signInQuestion: (name: string) => `Use ${name} to sign in to ILM?`,
    stopsWorking: (name: string) => `${name} stops working for sign-in.`,
    currentSignInCertificate: 'Your current sign-in certificate',
    useThisCertificate: 'Use this certificate',
    signInChangeFailed: 'ILM could not change your sign-in certificate.',
    certificatesInIlmCount: (total: number) => `${total.toLocaleString()} certificates in ILM`,
    searchByName: 'Search by name',
    ilmCertificatesListLabel: 'Certificates in ILM',
    ilmStateHeader: 'ILM state',
    previous: 'Previous',
    next: 'Next',
    pageRange: (from: number, to: number, total: number) =>
        `${from.toLocaleString()}\u2013${to.toLocaleString()} of ${total.toLocaleString()}`,
    noIlmCertificates: 'No certificates found in ILM.',
    ilmOffline: (at: number | null) =>
        at === null ? 'Search and paging need ILM.' : `Search and paging need ILM. Showing the first page from ${time(at)}.`,
    syncFailed: 'ILM could not be checked.',
    ilmLoadFailed: 'The certificates in ILM could not be read.',
    fingerprintTitle: 'Fingerprint (SHA-256)',
    settings: 'Settings',
    preferences: 'Preferences',
    settingsWindow: 'Settings…',
    general: 'General',
    startAtLogin: 'Start at login',
    logLevel: 'Log level',
    checkEvery: 'Check ILM every',
    warnBeforeExpiry: 'Warn before expiry',
    days: (count: number) => (count === 1 ? '1 day' : `${count} days`),
    managedByOrganization: 'Managed by your organization',
    switchOn: 'On',
    switchOff: 'Off',
    settingsLoadError: 'The settings could not be loaded.',
    settingFailed: 'The setting could not be changed.',
    openApp: 'Open Identity Manager',
    valid: 'Valid',
    expiringSoon: 'Expiring soon',
    expired: 'Expired',
    countsLabel: 'Certificates by state',
    needsAttention: 'Needs attention',
    nothingNeedsAttention: 'Nothing needs attention.',
    show: 'Show',
    showCertificate: (name: string) => `Show ${name}`,
    addToIlm: 'Add to ILM',
    revokedInIlm: 'Revoked in ILM',
    expiredOnDate: (date: string) => `Expired on ${date}`,
    expiresOnDate: (date: string, days: number) => `Expires ${when(date, days)}`,
    expiresOn: (date: string, days: number) => `expires ${when(date, days)}`,
    notInIlmCount: (count: number, platform: 'macos' | 'windows') =>
        `${count} ${count === 1 ? 'certificate' : 'certificates'} on this ${platform === 'macos' ? 'Mac' : 'PC'} ${count === 1 ? 'is' : 'are'} not in ILM`,
    notInIlmCountShort: (count: number) => `${count} ${count === 1 ? 'certificate is' : 'certificates are'} not in ILM`,
    nameList: (names: string[]) => (names.length < 2 ? names.join('') : `${names.slice(0, -1).join(', ')} and ${names.at(-1)}`),
    expiryChart: 'Expiry over the next 12 months',
    expiryChartLabel: 'Certificates expiring in each of the next 12 months',
    expiringList: 'Certificates expiring soon',
    month: (at: number) => new Intl.DateTimeFormat(undefined, { month: 'short' }).format(new Date(at)),
    noCertificatesWithKey: (platform: 'macos' | 'windows') =>
        `No certificates with a private key on this ${platform === 'macos' ? 'Mac' : 'PC'}.`,
    moreAttention: (count: number) => `+${count} more`,
    lastCheckedWithIlm: (at: number) => `Last checked with ILM at ${time(at)}`,
    addTitle: (count: number) => `Add ${count} ${count === 1 ? 'certificate' : 'certificates'} to ILM`,
    keysStayHere: (platform: 'macos' | 'windows') => `Private keys stay on this ${platform === 'macos' ? 'Mac' : 'PC'}`,
    certificatesToAdd: 'Certificates to add',
    expiresDate: (date: string) => `expires ${date}`,
    group: 'Group',
    raProfile: 'RA Profile',
    none: 'None',
    raProfileHint: 'With an RA Profile ILM manages the certificate and can renew it. Without one ILM only tracks it.',
    addCount: (count: number) => `Add ${count} to ILM`,
    adding: 'Adding…',
    close: 'Close',
    addResults: 'Results',
    added: 'Added',
    addedNotManaged: (reasons: string) => (reasons ? `Added, not managed: ${reasons}` : 'Added, not managed'),
    notAdded: (reasons: string) => (reasons ? `Not added: ${reasons}` : 'Not added'),
    addFailed: 'The certificates could not be added.',
    customAttributes: 'Custom attributes',
    attributeProblem,
    attributeConstraint,
    attributeUnsupported: (label: string) =>
        `${label}: Identity Manager cannot show this attribute. Fill it in in ILM\u2019s web interface.`,
    openInIlm: 'Open in ILM',
    openInIlmFailed: 'ILM\u2019s web interface could not be opened.',
    formNeedsIlm: 'This form needs ILM\u2019s web interface.',
    choicesUnavailable: 'ILM did not answer. Try again later.',
    attributesNeedAttention: 'Some attributes need your attention.',
    callbackFailed: 'ILM did not answer.',
    attributeCheckFailed: 'The attributes could not be checked.',
    attributeReadOnly: 'Set by ILM',
    attributeRequired: 'required',
    enterText: 'Enter text',
    enterSecret: 'Enter secret',
    enterScript: 'Enter script',
    enterJson: 'Enter JSON',
    wholeNumber: 'Whole number',
    number: 'Number',
    showSecret: 'Show',
    chooseFile: 'Choose file…',
    noFileChosen: 'No file chosen',
    remove: 'Remove',
    removeFile: (label: string) => `Remove ${label} file`,
    fileDescription: (name: string, bytes: number) => `${name}, ${fileSize(bytes)}`,
    fileSize,
    fileUnreadable: 'The file cannot be read.',
    fileEmpty: 'The file is empty.',
    selectValue: 'Select…',
    addValue: 'Add value',
    addValueTo: (label: string) => `Add value to ${label}`,
    add: 'Add',
    version: (version: string) => `Version ${version}`,
    loadError: 'Identity Manager could not load its details.',
    sessionLoadError: 'The sign-in state could not be loaded.',
    connectTitle: 'Connect to your ILM',
    connectHint: 'Enter the address of your ILM.',
    ilmAddress: 'ILM address',
    continue: 'Continue',
    welcomeTitle: 'Welcome',
    welcomeHint: 'Your organization has set up this ILM.',
    signIn: 'Sign in',
    chooseTitle: 'Choose how to sign in',
    chooseHint: 'Your ILM offers more than one way to sign in.',
    waitingTitle: 'Continue in your browser',
    waitingHint: (provider: string) => `Finish signing in with ${provider}, then return to this window.`,
    openBrowserAgain: 'Open the browser again',
    cancel: 'Cancel',
    back: 'Back',
    certificateEntry: 'Certificate on this computer',
    certificateTitle: 'Choose a certificate',
    certificateHint: 'Choose the certificate to sign in with.',
    certificateGroup: 'Certificates on this computer',
    certificateExpires: (notAfter: number) =>
        `Expires ${new Intl.DateTimeFormat(undefined, { dateStyle: 'medium' }).format(new Date(notAfter))}`,
    noCertificate: 'This computer has no certificate that can sign in.',
    certificateWaitingTitle: 'Signing in with your certificate',
    certificateWaitingHint: 'Your ILM is checking the certificate you chose.',
    certificateWaitingStatus: 'Checking the certificate with ILM…',
    connectFailed: 'Could not connect to this ILM.',
    connection: 'Connection',
    signOut: 'Sign out',
    signedInWithCertificate: 'Signed in with a certificate',
    lockedTitle: 'Identity Manager is locked',
    unlock: 'Unlock',
    unlockFailed: 'Identity Manager could not be unlocked.',
    signInAgain: 'Sign in again',
    signInEnded: 'Your sign-in has ended.',
    signedOutTitle: 'Signed out',
    summarySignedIn: (host: string, name: string) => `Signed in to ${host} as ${name}`,
    summaryUnreachable: (host: string) => `Cannot reach ${host}`,
    security: 'Security',
    unlockWithTouchId: 'Ask for Touch ID or your password to unlock',
    unlockWithHello: 'Ask for Windows Hello to unlock',
    lockAfterIdle: 'Lock after inactivity',
    never: 'Never',
    minutes: (count: number) => `${count} minutes`,
    setUpHello: 'Set up Windows Hello to lock Identity Manager.',
    setUpPassword: 'Set a password for this Mac to lock Identity Manager.',

    requestCertificate: 'Request certificate',
    requestTitle: 'Request a certificate',
    requestSteps: 'Steps',
    requestStepNames: ['Profile', 'Attributes', 'Private key', 'Review'],
    stepDone: 'done',
    chooseProfile: 'Choose an RA profile',
    chooseProfileHint: 'These are the RA profiles ILM lets you use.',
    profiles: 'RA profiles',
    authorityNamed: (name: string) => `Authority: ${name}`,
    fillAttributes: 'Fill in the attributes',
    certificateRequestGroup: 'Certificate request',
    raProfileGroup: 'From the RA profile',
    requestFormsLoading: 'Loading the attributes…',
    requestFormsFailed: 'The attributes could not be loaded.',
    keyHome: 'Where should the private key live?',
    keyStaysHere: (platform: Platform) =>
        `The key is created on ${{ macos: 'this Mac', windows: 'this PC', linux: 'this computer' }[platform]} and never leaves it.`,
    keyStorages: 'Key storage',
    recommended: 'Recommended',
    keyType: 'Key type',
    offersLoading: 'Checking the key storages…',
    offersFailed: 'The key storages could not be read.',
    noKeyStorage: 'Your organization does not allow a key storage on this computer.',
    storageName: (storage: string, platform: Platform): string => {
        if (storage === 'software' && platform === 'windows') {
            return 'Windows key store';
        }
        return ({ keychain: 'Keychain', tpm: 'TPM', software: 'Software key' } as Record<string, string>)[storage] ?? storage;
    },
    storageDescription: (storage: string, platform: Platform) => {
        if (storage === 'keychain') {
            return 'In your login keychain, marked as not exportable.';
        }
        if (storage === 'tpm') {
            return `Protected by the security chip in ${platform === 'windows' ? 'this PC' : 'this computer'}. Cannot be copied.`;
        }
        return platform === 'windows'
            ? 'In your user profile, marked as not exportable.'
            : 'Kept on this computer for your user account only.';
    },
    keyTypeNames: {
        ecP256: 'EC P-256',
        ecP384: 'EC P-384',
        ecP521: 'EC P-521',
        rsa2048: 'RSA 2048',
        rsa3072: 'RSA 3072',
        rsa4096: 'RSA 4096',
        mlDsa44: 'ML-DSA-44',
        mlDsa65: 'ML-DSA-65',
        mlDsa87: 'ML-DSA-87',
    } as Record<string, string>,
    reviewTitle: 'Review and request',
    reviewProfile: 'Profile',
    reviewSubject: 'Subject',
    reviewKey: 'Private key',
    reviewKeyType: 'Key type',
    reviewInstalledIn: 'Installed in',
    reviewNewKey: (where: string) => `New, in ${where}`,
    keyPlace: (storage: string, platform: Platform) => {
        if (storage === 'keychain') {
            return 'the keychain';
        }
        if (storage === 'tpm') {
            return 'the TPM';
        }
        return platform === 'windows' ? 'the Windows key store' : 'software';
    },
    installedPlace: (platform: Platform) => (platform === 'macos' ? 'Your login keychain' : 'Your personal certificate store'),
    requestPlan: (where: string) => [
        `A new key is created in ${where}.`,
        'A request signed with that key goes to ILM. The key itself is never sent.',
        'ILM issues the certificate and this app installs it with its intermediates.',
    ],
    requestPlanName: 'What happens next',
    requesting: 'Requesting…',
    requestRefused: 'ILM did not accept the request',
    requestFailed: 'The certificate could not be requested.',
    installedTitle: 'Your certificate is installed',
    installedIn: (label: string, platform: Platform) =>
        `${label} is in ${platform === 'macos' ? 'your login keychain' : 'your personal certificate store'}.`,
    requestValidUntil: 'Valid until',
    waitingForApproval: 'Waiting for approval',
    beingIssued: 'Being issued',
    requestsInProgress: 'Requests in progress',
    issuing: 'ILM is issuing your certificate',
    installWhenIssued: 'The app installs it when ILM issues it. You can close this window.',
    requestRejected: 'ILM rejected the request.',
    requestNotIssued: 'ILM could not issue the certificate.',
    requestIssuedNotInstalled: 'ILM issued the certificate, but it could not be installed. The app will try again.',
    requestOtherKey: 'ILM issued a certificate that does not match the key created for this request.',
    done: 'Done',

    requests: 'Requests',
    requestsSummary: (waiting: number, ready: number, inProgress: number) =>
        [
            waiting > 0 && `${waiting} waiting for your approval`,
            ready > 0 && `${ready} ready to issue`,
            inProgress > 0 && `${inProgress} in progress`,
        ]
            .filter(Boolean)
            .join(', '),
    waitingForYourApproval: 'Waiting for your approval',
    approve: 'Approve',
    approveNamed: (name: string) => `Approve ${name}`,
    reject: 'Reject',
    rejectEllipsis: 'Reject…',
    rejectNamed: (name: string) => `Reject ${name}`,
    approvalCertificate: 'Certificate',
    approvalFrom: (requester: string | null, raProfile: string | null) =>
        [requester && `From ${requester}`, raProfile].filter(Boolean).join(' \u00b7 '),
    approvalKinds: { issue: 'New certificate', renew: 'Renewal', rekey: 'Rekey', revoke: 'Revocation' },
    approvalKindsAsked: { issue: 'a new certificate', renew: 'a renewal', rekey: 'a rekey', revoke: 'a revocation' },
    approvalStatus: (kind: string, at: number) => `${kind}, ${time(at)}`,
    rejectTitle: (name: string) => `Reject the request for ${name}?`,
    rejectText: (requester: string | null, asked: string, raProfile: string | null) => {
        const where = raProfile ? ` in ${raProfile}` : '';
        return `${requester ?? 'Someone'} asked for ${asked}${where}. Rejecting ends the request.`;
    },
    rejectComment: 'Comment (optional)',
    rejectCommentHint: 'ILM keeps the comment with the approval.',
    approvalNoLongerWaiting: 'This request no longer waits for your decision.',
    approvalFailed: 'The decision could not be sent.',
    readyToIssue: 'Ready for you to issue',
    myRequests: 'My requests',
    issue: 'Issue…',
    issueTitle: (name: string) => `Issue ${name}`,
    issueNamed: (name: string) => `Issue ${name}`,
    issueWithin: (days: number) => `Issue within ${days} ${days === 1 ? 'day' : 'days'}`,
    issueWindowEnded: 'Issue window ended',
    lockedAfterAttempts: 'Locked after too many attempts',
    askAdministrator: 'Ask your administrator',
    requestedAt: (at: number) => `Requested ${time(at)}`,
    nothingToIssue: 'Nothing to issue or follow',
    nothingToIssueHint: 'Certificates your administrator prepares for you and the requests you send appear here.',
    preparedBy: 'Prepared by your administrator',
    raProfileLabel: 'RA profile',
    reviewCertificate: 'Certificate',
    challenge: 'Challenge',
    challengeHint: 'Your administrator gives you this with the certificate.',
    issueCertificate: 'Issue certificate',
    subjectLabels: {
        commonName: 'Name',
        organization: 'Organization',
        organizationalUnit: 'Organizational unit',
        country: 'Country',
        state: 'State or province',
        locality: 'Locality',
        email: 'Email in the certificate',
        serialNumber: 'Serial number',
        domainComponent: 'Domain component',
        other: 'Other',
        dns: 'DNS name',
        ip: 'IP address',
        uri: 'URI',
        upn: 'User principal name',
    } satisfies Record<SubjectKind, string>,
    renewalGroupTitle: 'Renewal',
    renewAutomatically: 'Renew automatically',
    renewWhenRow: 'When',
    daysBeforeExpiry: (count: number) => `${count === 1 ? '1 day' : `${count} days`} before expiry`,
    renewalFrom: (date: string) => `From ${date}`,
    renewKeyRow: 'Private key',
    renewNewKey: 'New key each time',
    renewSameKey: 'Same key',
    renewalHint: 'While you are signed in, the app renews this certificate.',
    renewNow: 'Renew now',
    renew: 'Renew',
    renewName: (name: string) => `Renew ${name}`,
    renewing: 'Renewing…',
    renewalInProgress: 'Renewal in progress…',
    renewalWaitingForApproval: 'Renewal waiting for approval',
    renewalDone: 'Renewed. The new certificate is installed.',
    renewalRejected: 'ILM rejected the renewal.',
    renewalNotIssued: 'ILM could not renew the certificate.',
    renewalNotInstalled: 'ILM renewed the certificate, but it could not be installed. The app will try again.',
    renewalFailed: 'The certificate could not be renewed.',
    renewalSwitchFailed: 'The switch could not be changed.',
    replacedByRenewal: 'Replaced by renewal',
    showRenewedCertificate: 'Show the new certificate',
    replacedByRenewalOn: (date: string) => `Replaced by renewal on ${date}`,
    automaticRenewal: 'Automatic renewal',
    automaticRenewalChoices: { off: 'Off', newKey: 'New key', sameKey: 'Same key' } satisfies Record<AutomaticRenewal, string>,
};
