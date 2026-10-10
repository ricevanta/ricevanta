import js from '@eslint/js'
import ts from 'typescript-eslint'
import vue from 'eslint-plugin-vue'
import rv from './scripts/eslint-rules/index.mjs'
export default ts.config(
  {
    ignores: [
      'dist/**',
      'node_modules/**',
      'src/generated/**',
      'public/brand/**',
      'tests/fixtures/**',
      'playwright-report/**',
      'test-results/**',
    ],
  },
  js.configs.recommended,
  ...ts.configs.strictTypeChecked,
  ...vue.configs['flat/recommended'],
  {
    files: ['**/*.ts', '**/*.vue'],
    languageOptions: {
      parserOptions: {
        parser: ts.parser,
        project: ['./tsconfig.app.json', './tsconfig.tools.json', './tsconfig.test.json'],
        extraFileExtensions: ['.vue'],
      },
    },
    rules: {
      '@typescript-eslint/switch-exhaustiveness-check': 'error',
      'vue/multi-word-component-names': 'off',
      'vue/max-attributes-per-line': 'off',
      'vue/singleline-html-element-content-newline': 'off',
      'vue/html-self-closing': 'off',
      'vue/html-indent': 'off',
      'vue/html-closing-bracket-newline': 'off',
      'no-undef': 'off',
    },
  },
  { files: ['src/**/*.ts', 'src/**/*.vue'], plugins: { rv }, rules: { 'rv/foundation': 'error' } },
  {
    files: ['**/*.mjs'],
    ...ts.configs.disableTypeChecked,
    languageOptions: { globals: { Set: 'readonly' } },
  },
)
