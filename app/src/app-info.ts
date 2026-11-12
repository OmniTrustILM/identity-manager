import { createContext, useContext } from 'react';
import type { AppInfo } from './bridge';

export const AppInfoContext = createContext<AppInfo | null>(null);

export function useAppInfo(): AppInfo {
    const info = useContext(AppInfoContext);
    if (!info) {
        throw new Error('The app information is not available here.');
    }
    return info;
}
