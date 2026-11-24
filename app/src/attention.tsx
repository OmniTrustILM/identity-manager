import type { AttentionItemView } from './bridge';
import { ExpiredIcon, ExpiringIcon, type Icon, NotInIlmIcon, RevokedIcon } from './design-system/icons';
import { strings } from './strings';

/** The item of an attention list that is about one certificate. */
export type CertificateItem = Exclude<AttentionItemView, { kind: 'notInIlm' | 'waiting' }>;

/** The icon of an item with its colour, and the colour of its text. */
export function attentionLook(item: AttentionItemView): { Icon: Icon; tone: string; textTone: string } {
    switch (item.kind) {
        case 'expiring':
            return { Icon: ExpiringIcon, tone: 'text-attention', textTone: 'text-attention-text' };
        case 'expired':
            return { Icon: ExpiredIcon, tone: 'text-bad', textTone: 'text-bad' };
        case 'revoked':
            return { Icon: RevokedIcon, tone: 'text-bad', textTone: 'text-bad' };
        case 'waiting':
            return { Icon: ExpiringIcon, tone: 'text-accent', textTone: 'text-secondary' };
        default:
            return { Icon: NotInIlmIcon, tone: 'text-secondary', textTone: 'text-secondary' };
    }
}

/** What is the matter with the certificate of an item, in words. */
export function attentionDetail(item: CertificateItem): string {
    switch (item.kind) {
        case 'expiring':
            return strings.expiresOnDate(strings.date(item.on), item.days);
        case 'expired':
            return strings.expiredOnDate(strings.date(item.on));
        default:
            return strings.revokedInIlm;
    }
}

/** What a request in progress waits for, in words. */
export function waitingDetail(item: Extract<AttentionItemView, { kind: 'waiting' }>): string {
    return item.state === 'pendingApproval' ? strings.waitingForApproval : strings.beingIssued;
}
