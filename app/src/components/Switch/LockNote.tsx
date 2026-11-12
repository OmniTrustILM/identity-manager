import { LockIcon } from '../../design-system/icons';
import { strings } from '../../strings';

/** Says why a setting cannot be changed; the control it belongs to points at it with `aria-describedby`. */
export function LockNote({ id }: Readonly<{ id: string }>) {
    return (
        <p id={id} className="flex items-center gap-s1 text-caption text-secondary">
            <LockIcon aria-hidden className="size-icon shrink-0" />
            {strings.managedByOrganization}
        </p>
    );
}
