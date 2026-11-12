import { defineConfig, devices } from '@playwright/experimental-ct-react';
import tailwindcss from '@tailwindcss/vite';
import react from '@vitejs/plugin-react-swc';

export default defineConfig({
    testDir: './src',
    testMatch: '**/*.ct.tsx',
    timeout: 30 * 1000,
    fullyParallel: true,
    forbidOnly: !!process.env.CI,
    reporter: 'list',
    use: {
        ctPort: 3100,
        ctViteConfig: {
            plugins: [react(), tailwindcss()],
        },
    },
    projects: [
        { name: 'chromium', use: { ...devices['Desktop Chrome'] } },
        { name: 'webkit', use: { ...devices['Desktop Safari'] } },
    ],
});
