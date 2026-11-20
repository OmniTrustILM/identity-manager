export {
    CircleAlert as ProblemIcon,
    CircleCheck as FineIcon,
    Globe as ConnectionIcon,
    Info as InfoIcon,
    ChevronsUpDown as SelectIcon,
    LayoutGrid as OverviewIcon,
    LoaderCircle as BusyIcon,
    Lock as LockIcon,
    WifiOff as UnreachableIcon,
    Settings as SettingsIcon,
    ShieldCheck as AppIcon,
    type LucideIcon as Icon,
} from 'lucide-react';
import { createLucideIcon } from 'lucide-react';

/** A certificate with its ribbon. */
export const CertificateIcon = createLucideIcon('certificate', [
    ['rect', { x: '3', y: '4', width: '18', height: '12', rx: '2', key: 'card' }],
    ['path', { d: 'M7 8.5h6M7 11.5h4', key: 'lines' }],
    ['circle', { cx: '16.5', cy: '11', r: '2', key: 'seal' }],
    ['path', { d: 'M15.2 13v6l1.3-1 1.3 1v-6', key: 'ribbon' }],
]);
