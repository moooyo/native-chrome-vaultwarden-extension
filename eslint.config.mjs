import js from '@eslint/js';
import tseslint from 'typescript-eslint';
import globals from 'globals';

export default tseslint.config(
  { ignores: ['dist/**', 'node_modules/**', 'test-results/**', 'claude-design/**', 'tools/verify-render.mjs', 'tools/verify-e2e.mjs', 'tools/verify-panels.mjs', 'test-page/verify-testpage.mjs'] },
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
    rules: {
      'no-console': 'off',
      // Allow intentionally-unused identifiers prefixed with `_` (e.g. ignored callback params).
      '@typescript-eslint/no-unused-vars': ['error', { argsIgnorePattern: '^_', varsIgnorePattern: '^_', caughtErrorsIgnorePattern: '^_' }],
    },
  },
);
