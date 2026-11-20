import { type KeyboardEvent, type ReactNode, useEffect, useId, useRef } from 'react';
import { strings } from '../../strings';

const primary = 'h-button rounded-control bg-accent px-s3 text-body text-on-accent disabled:opacity-disabled';
const secondary = 'h-button rounded-control border border-button-edge bg-button px-s3 text-body text-primary disabled:opacity-disabled';

/**
 * A question over the page with a confirming and a cancelling button, in the order of the system:
 * Cancel first on macOS, the confirming button first on Windows. Escape cancels; Tab stays inside.
 * While busy the question can no longer be withdrawn, so Cancel is off and Escape does nothing.
 */
export function ConfirmDialog({
    title,
    children,
    confirmLabel,
    busy,
    macos,
    onConfirm,
    onCancel,
}: Readonly<{
    title: string;
    children?: ReactNode;
    confirmLabel: string;
    busy: boolean;
    macos: boolean;
    onConfirm: () => void;
    onCancel: () => void;
}>) {
    const titleId = useId();
    const messageId = useId();
    const panel = useRef<HTMLDivElement>(null);
    const confirm = useRef<HTMLButtonElement>(null);

    useEffect(() => {
        const before = document.activeElement as HTMLElement | null;
        confirm.current?.focus();
        return () => before?.focus();
    }, []);

    const keys = (event: KeyboardEvent) => {
        if (event.key === 'Escape') {
            event.preventDefault();
            if (!busy) {
                onCancel();
            }
            return;
        }
        if (event.key !== 'Tab') {
            return;
        }
        const buttons = [...(panel.current?.querySelectorAll<HTMLButtonElement>('button:not(:disabled)') ?? [])];
        const first = buttons[0];
        const last = buttons[buttons.length - 1];
        if (event.shiftKey && document.activeElement === first) {
            event.preventDefault();
            last?.focus();
        } else if (!event.shiftKey && document.activeElement === last) {
            event.preventDefault();
            first?.focus();
        }
    };

    const confirmButton = (
        <button ref={confirm} tabIndex={0} type="button" disabled={busy} onClick={onConfirm} className={primary}>
            {confirmLabel}
        </button>
    );
    const cancelButton = (
        <button tabIndex={0} type="button" disabled={busy} onClick={onCancel} className={secondary}>
            {strings.cancel}
        </button>
    );

    return (
        <div className="fixed inset-0 z-10 flex items-center justify-center bg-primary/40">
            <div
                ref={panel}
                role="dialog"
                aria-modal="true"
                aria-labelledby={titleId}
                aria-describedby={children ? messageId : undefined}
                onKeyDown={keys}
                className="box-content flex w-form flex-col gap-s3 rounded-window border border-separator bg-surface p-s5"
            >
                <h2 id={titleId} className="text-title font-semibold text-primary">
                    {title}
                </h2>
                {children && (
                    <p id={messageId} className="text-body text-secondary">
                        {children}
                    </p>
                )}
                <div className="flex justify-end gap-s2 pt-s2">
                    {macos ? cancelButton : confirmButton}
                    {macos ? confirmButton : cancelButton}
                </div>
            </div>
        </div>
    );
}
