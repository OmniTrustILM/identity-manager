import { createContext, useContext } from 'react';

/** A request to show one certificate; `id` tells a repeated request for the same certificate from the one before. */
export interface Showing {
    fingerprint: string;
    id: number;
}

interface Navigation {
    /** The certificate the person was sent to, until they choose a section themselves. */
    showing: Showing | null;
    /** Opens Certificates with this certificate selected. */
    showCertificate: (fingerprint: string) => void;
}

export const NavigationContext = createContext<Navigation>({ showing: null, showCertificate: () => undefined });

export const useNavigation = () => useContext(NavigationContext);
