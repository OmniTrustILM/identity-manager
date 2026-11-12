import { fileURLToPath } from 'node:url';
import react from '@vitejs/plugin-react-swc';
import { defineConfig } from 'vitest/config';

const repositoryRoot = fileURLToPath(new URL('..', import.meta.url));

export default defineConfig({
    plugins: [react()],
    test: {
        environment: 'happy-dom',
        include: ['src/**/*.spec.{ts,tsx}'],
        exclude: ['**/node_modules/**', '**/*.ct.tsx', 'playwright/**'],
        coverage: {
            provider: 'v8',
            include: ['src/**/*.{ts,tsx}'],
            exclude: ['src/main.tsx', 'src/**/*.spec.{ts,tsx}', 'src/**/*.ct.tsx', 'playwright/**'],
            reportsDirectory: 'coverage-vitest',
            reporter: ['text-summary', ['lcovonly', { projectRoot: repositoryRoot }]],
            thresholds: { lines: 80, functions: 80, branches: 80, statements: 80 },
        },
    },
});
