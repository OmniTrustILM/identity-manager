import type { AttributeFieldView, AttributeFormView } from '../src/bridge';

/** A field of an attribute form with nothing set but a name and a label. */
export const attributeField = (name: string, over: Partial<AttributeFieldView> = {}): AttributeFieldView => ({
    name,
    label: name,
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

/** A form of one ungrouped part. */
export const attributeForm = (fields: AttributeFieldView[], over: Partial<AttributeFormView> = {}): AttributeFormView => ({
    id: 'form-1',
    revision: 0,
    groups: [{ title: null, fields }],
    unsupported: [],
    web: null,
    ...over,
});

/** Extensible lists: a single list of integers and a single list of dates. */
export const extensibleFields: AttributeFieldView[] = [
    attributeField('number', {
        label: 'Extensible List Number',
        kind: 'select',
        extensible: true,
        valueKind: 'integer',
        options: [
            { key: 'k0', label: '1' },
            { key: 'k1', label: '2' },
        ],
    }),
    attributeField('day', {
        label: 'Extensible List Date',
        kind: 'select',
        extensible: true,
        valueKind: 'date',
        options: [{ key: 'k0', label: '2026-01-01' }],
    }),
    attributeField('moment', { label: 'Extensible List DateTime', kind: 'multiselect', extensible: true, valueKind: 'dateTime' }),
];

const levels = [
    { key: 'k0', label: 'Low' },
    { key: 'k1', label: 'Medium' },
    { key: 'k2', label: 'High' },
];

/** One field of every control, with the values ILM would give them. */
export const controlFields: AttributeFieldView[] = [
    attributeField('owner', { label: 'Owner', required: true, description: 'Who looks after it.' }),
    attributeField('description', { label: 'Description', kind: 'textarea' }),
    attributeField('apiKey', { label: 'API key', kind: 'secret', required: true }),
    attributeField('count', { label: 'TestInt', kind: 'integer', constraints: [{ kind: 'range', min: 1, max: 99 }] }),
    attributeField('threshold', { label: 'Threshold', kind: 'float' }),
    attributeField('notify', { label: 'Notify owner', kind: 'switch', value: { kind: 'bool', value: false } }),
    attributeField('review', { label: 'Review date', kind: 'date' }),
    attributeField('window', { label: 'Window start', kind: 'time' }),
    attributeField('until', { label: 'Valid until', kind: 'datetime' }),
    attributeField('template', { label: 'Template', kind: 'file' }),
    attributeField('script', { label: 'Script', kind: 'code', language: 'bash' }),
    attributeField('settings', { label: 'Settings', kind: 'json' }),
    attributeField('level', { label: 'Importance level', kind: 'select', options: levels }),
    attributeField('validity', { label: 'Validity', kind: 'select', options: levels, required: true }),
    attributeField('department', { label: 'Department', kind: 'multiselect', options: levels }),
    attributeField('contacts', {
        label: 'Contact emails',
        kind: 'multiselect',
        extensible: true,
        valueKind: 'text',
        options: [
            { key: 'k0', label: 'ops@example.com' },
            { key: 'k1', label: 'sec@example.com' },
        ],
    }),
    attributeField('note', {
        label: 'Note',
        kind: 'info',
        value: { kind: 'text', value: 'Attributes marked with a lock are set by ILM.' },
    }),
    attributeField('fixed', { label: 'Cost owner', readOnly: true, value: { kind: 'text', value: 'Alex Morgan' } }),
];

/** The request attributes (v3) and issue attributes (v2) of a demo RA Profile. */
export const issueForm: AttributeFormView = {
    id: 'issue-1',
    revision: 0,
    unsupported: [],
    web: null,
    groups: [
        {
            title: 'Request attributes',
            fields: [
                attributeField('common-name', {
                    label: 'Common name',
                    required: true,
                    readOnly: true,
                    value: { kind: 'text', value: 'device-01.demo.example' },
                }),
                attributeField('san', {
                    label: 'Subject alternative names',
                    kind: 'multiselect',
                    extensible: true,
                    valueKind: 'text',
                    options: [
                        { key: 'k0', label: 'device-01.demo.example' },
                        { key: 'k1', label: 'device-01' },
                    ],
                    value: { kind: 'options', value: [{ kind: 'option', value: 'k0' }] },
                }),
                attributeField('service-entitlement', {
                    label: 'Service entitlement',
                    kind: 'select',
                    options: [
                        { key: 'k0', label: 'Standard' },
                        { key: 'k1', label: 'Premium' },
                    ],
                    value: { kind: 'option', value: 'k0' },
                }),
            ],
        },
        {
            title: 'Issue attributes',
            fields: [
                attributeField('email', {
                    label: 'Email',
                    required: true,
                    constraints: [{ kind: 'pattern', description: 'An address at example.com.' }],
                }),
                attributeField('issue-san', {
                    label: 'DNS names',
                    kind: 'multiselect',
                    extensible: true,
                    valueKind: 'text',
                    options: [{ key: 'k0', label: 'device-01.demo.example' }],
                }),
                attributeField('extension', { label: 'Extension', kind: 'textarea' }),
            ],
        },
    ],
};

/** A form with a required attribute the application cannot show. */
export const unsupportedForm: AttributeFormView = attributeForm(
    [
        attributeField('qa', { label: 'qa_test_custom_attr', required: true, value: { kind: 'text', value: 'qa-default' } }),
        attributeField('department', { label: 'department', kind: 'multiselect', options: levels }),
    ],
    { unsupported: ['Cost center'], web: 'https://ilm.example/administrator/#/certificates' },
);
