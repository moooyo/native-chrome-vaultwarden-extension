import js from '@eslint/js';
import tseslint from 'typescript-eslint';
import globals from 'globals';

export default tseslint.config(
  { ignores: ['dist/**', 'node_modules/**', 'test-results/**', 'claude-design/**', 'tools/verify-render.mjs', 'tools/verify-e2e.mjs', 'tools/verify-panels.mjs'] },
  js.configs.recommended,
  ...tseslint.configs.recommended,
  {
    languageOptions: {
      globals: {
        ...globals.node,
        chrome: 'readonly',
        browser: 'readonly',
        btoa: 'readonly',
        atob: 'readonly',
      },
    },
    rules: { 'no-console': 'off' },
  },
);
