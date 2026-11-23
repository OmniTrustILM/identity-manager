import { useState } from 'react';
import { type IlmTarget, openInIlm } from '../../bridge';
import { ExternalIcon, WarningIcon } from '../../design-system/icons';
import { strings } from '../../strings';

/** A required attribute this application cannot show, with the way to fill it in in ILM's web interface. */
export function UnsupportedRow({ label, target, disabled }: Readonly<{ label: string; target: IlmTarget; disabled: boolean }>) {
    const [failed, setFailed] = useState(false);
    return (
        <div className="flex flex-col gap-s1">
            <div className="flex items-center gap-s3 rounded-control border border-separator px-s3 py-s2">
                <WarningIcon aria-hidden className="size-icon shrink-0 text-attention" />
                <p className="min-w-0 flex-1 text-body text-primary">{strings.attributeUnsupported(label)}</p>
                <button
                    type="button"
                    tabIndex={0}
                    disabled={disabled}
                    onClick={() =>
                        openInIlm(target).then(
                            () => setFailed(false),
                            () => setFailed(true),
                        )
                    }
                    className="flex h-control shrink-0 items-center gap-s1 rounded-control border border-button-edge bg-button px-s3 text-body text-primary disabled:opacity-disabled"
                >
                    {strings.openInIlm}
                    <ExternalIcon aria-hidden className="size-icon" />
                </button>
            </div>
            {failed && (
                <p role="alert" className="text-caption text-bad">
                    {strings.openInIlmFailed}
                </p>
            )}
        </div>
    );
}
