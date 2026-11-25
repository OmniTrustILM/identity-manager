import { type ReactNode, type SyntheticEvent, useEffect, useId, useRef } from 'react';
import { strings } from '../../strings';

const primary = 'h-button rounded-control bg-accent px-s3 text-body text-on-accent disabled:opacity-disabled';
const secondary = 'h-button rounded-control border border-button-edge bg-button px-s3 text-body text-primary disabled:opacity-disabled';

/**
 * A question over the page with a confirming and a cancelling button, in the order of the system:
 * Cancel first on macOS, the confirming button first on Windows. Escape cancels; the page behind is inert, so focus stays inside.
 * While busy the question can no longer be withdrawn, so Cancel is off and Escape does nothing.
 */
export function ConfirmDialog({
    title,
    children,
    extra,
    confirmLabel,
    busy,
    macos,
    onConfirm,
    onCancel,
}: Readonly<{
    title: string;
    children?: ReactNode;
    /** More under the message, such as a field or an error. */
    extra?: ReactNode;
    confirmLabel: string;
    busy: boolean;
    macos: boolean;
    onConfirm: () => void;
    onCancel: () => void;
}>) {
    const titleId = useId();
    const messageId = useId();
    const panel = useRef<HTMLDialogElement>(null);
    const confirm = useRef<HTMLButtonElement>(null);

    useEffect(() => {
        const before = document.activeElement as HTMLElement | null;
        panel.current?.showModal();
        confirm.current?.focus();
        return () => before?.focus();
    }, []);

    useEffect(() => {
        if (busy) {
            panel.current?.focus();
        }
    }, [busy]);

    const closing = (event: SyntheticEvent) => {
        event.preventDefault();
        if (!busy) {
            onCancel();
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
        <dialog
            ref={panel}
            tabIndex={-1}
            aria-labelledby={titleId}
            aria-describedby={children ? messageId : undefined}
            onCancel={closing}
            className="m-auto box-content flex w-form flex-col gap-s3 rounded-window border border-separator bg-surface p-s5 text-primary backdrop:bg-primary/40"
        >
            <h2 id={titleId} className="text-title font-semibold text-primary">
                {title}
            </h2>
            {children && (
                <p id={messageId} className="text-body text-secondary">
                    {children}
                </p>
            )}
            {extra}
            <div className="flex justify-end gap-s2 pt-s2">
                {macos ? cancelButton : confirmButton}
                {macos ? confirmButton : cancelButton}
            </div>
        </dialog>
    );
}
