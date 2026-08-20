import js from '@eslint/js';
import globals from 'globals';

export default [
  js.configs.recommended,
  {
    files: ['**/*.js', '**/*.mjs'],
    languageOptions: {
      ecmaVersion: 2024,
      sourceType: 'module',
      globals: { ...globals.node }
    },
    rules: { 'no-unused-vars': ['error', { argsIgnorePattern: '^_' }] }
  },
  { ignores: ['node_modules/**', 'data/**', 'client/node_modules/**'] }
];
