import type { AttentionItemView } from './bridge';
import { ExpiredIcon, ExpiringIcon, type Icon, NotInIlmIcon, RevokedIcon } from './design-system/icons';
import { strings } from './strings';

/** The item of an attention list that is about one certificate. */
export type CertificateItem = Exclude<AttentionItemView, { kind: 'notInIlm' }>;

/** The icon and colour of an item. */
export function attentionLook(item: AttentionItemView): { Icon: Icon; tone: string } {
    switch (item.kind) {
        case 'expiring':
            return { Icon: ExpiringIcon, tone: 'text-attention' };
        case 'expired':
            return { Icon: ExpiredIcon, tone: 'text-bad' };
        case 'revoked':
            return { Icon: RevokedIcon, tone: 'text-bad' };
        default:
            return { Icon: NotInIlmIcon, tone: 'text-secondary' };
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
