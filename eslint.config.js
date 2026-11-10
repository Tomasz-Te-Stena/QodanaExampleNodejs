const js = require('@eslint/js');
const security = require('eslint-plugin-security');

module.exports = [
    // ==========================================================
    // FILES ESLINT SHOULD IGNORE
    // ==========================================================
    {
        ignores: [
            'node_modules/**',
            'coverage/**',
            'reports/**',
            '.stryker-tmp/**',
            '.idea/**'
        ],
    },

    // ==========================================================
    // ESLINT RECOMMENDED RULES
    // ==========================================================
    js.configs.recommended,

    // ==========================================================
    // SECURITY RULES (linter-level SAST, like Roslyn analyzers)
    // Flags child_process with variable input, non-literal fs
    // paths, unsafe RegExp, eval-like calls, ... Rules are
    // warnings, so they show in the IDE and in the pipeline log
    // without failing the build (Semgrep is the blocking SAST).
    // ==========================================================
    security.configs.recommended,

    // ==========================================================
    // NODE.JS APPLICATION
    // ==========================================================
    {
        files: ['**/*.js'],

        languageOptions: {
            ecmaVersion: 'latest',
            sourceType: 'commonjs',

            globals: {
                // Node.js
                console: 'readonly',
                process: 'readonly',
                require: 'readonly',
                module: 'readonly',
                __dirname: 'readonly',
                __filename: 'readonly',
                URL: 'readonly',

                // Jest
                describe: 'readonly',
                test: 'readonly',
                expect: 'readonly',
                beforeAll: 'readonly',
                afterAll: 'readonly',
                beforeEach: 'readonly',
                afterEach: 'readonly',
                jest: 'readonly',
            },
        },

        rules: {
            // Keep this as warning because our deliberately
            // vulnerable example may have unused callback args.
            'no-unused-vars': 'warn',

            'no-undef': 'error',

            // console.log is acceptable for this Node.js project.
            'no-console': 'off',
        },
    },
];