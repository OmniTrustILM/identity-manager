import { createContext, useContext } from 'react';

/** Whether the saved sign-in waits for ILM, so that nothing can be asked of ILM and what is shown is kept. */
export const IlmWaitingContext = createContext(false);

export const useIlmWaiting = () => useContext(IlmWaitingContext);
