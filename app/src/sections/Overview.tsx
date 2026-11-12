import { useAppInfo } from '../app-info';
import { strings } from '../strings';

export function Overview() {
    const info = useAppInfo();
    return (
        <>
            <h1 className="text-large-title">{info.name}</h1>
            <p className="text-secondary">{strings.version(info.version)}</p>
        </>
    );
}
