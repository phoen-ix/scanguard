import { defineConfig } from 'eslint/config'
import tseslint from 'typescript-eslint'

// Type-aware, for the one rule that matters most in Playwright code: an
// un-awaited promise (a forgotten `await` before an expect or an action) lets
// the test run on before the step has happened, and passes by accident.
export default defineConfig({
  files: ['**/*.ts'],
  ignores: ['node_modules/**'],
  languageOptions: { parser: tseslint.parser, parserOptions: { projectService: true, tsconfigRootDir: import.meta.dirname } },
  plugins: { '@typescript-eslint': tseslint.plugin },
  rules: {
    '@typescript-eslint/no-floating-promises': 'error',
    '@typescript-eslint/no-misused-promises': 'error',
    '@typescript-eslint/await-thenable': 'error',
  },
})
