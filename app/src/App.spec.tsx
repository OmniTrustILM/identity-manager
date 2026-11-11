import { renderToStaticMarkup } from 'react-dom/server';
import { expect, test } from 'vitest';
import { App } from './App';

test('renders the product name as the only level-one heading', () => {
    const markup = renderToStaticMarkup(<App />);
    const document = new DOMParser().parseFromString(markup, 'text/html');

    const headings = document.querySelectorAll('h1');

    expect(headings).toHaveLength(1);
    expect(headings[0]?.textContent).toBe('Identity Manager');
});
