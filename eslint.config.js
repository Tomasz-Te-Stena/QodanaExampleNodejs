const js = require('@eslint/js');

module.exports = [
    // ==========================================================
    // FILES ESLINT SHOULD IGNORE
    // ==========================================================
    {
        ignores: [
            'node_modules/**',
            'coverage/**',
            '.idea/**'
        ],
    },

    // ==========================================================
    // ESLINT RECOMMENDED RULES
    // ==========================================================
    js.configs.recommended,

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