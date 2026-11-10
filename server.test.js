// server.js destructures execFile at load time, so it must be mocked
// before server.js is required. No real shell command ever runs.
jest.mock('child_process', () => ({
    ...jest.requireActual('child_process'),
    execFile: jest.fn()
}));

const request = require('supertest');
const http = require('http');
const fs = require('fs');
const crypto = require('crypto');
const { Buffer } = require('buffer');
const { execFile } = require('child_process');

const fc = require('fast-check');

const { requestHandler, isValidHost, isSafeRedirect } = require('./server');

describe('Vulnerable REST API', () => {

    const server = http.createServer(requestHandler);

    afterEach(() => {
        jest.restoreAllMocks();
        execFile.mockReset();
    });

    test('GET /api/current_time returns current time', async () => {
        const beforeRequest = Date.now();

        const response = await request(server)
            .get('/api/current_time')
            .expect(200)
            .expect('Content-Type', /json/);

        const afterRequest = Date.now();

        expect(response.body).toHaveProperty('currentTime');

        const returnedTime = Date.parse(response.body.currentTime);

        // Verify it is a valid ISO date/time.
        expect(returnedTime).not.toBeNaN();

        // Verify the returned timestamp was generated during this request.
        expect(returnedTime).toBeGreaterThanOrEqual(beforeRequest);
        expect(returnedTime).toBeLessThanOrEqual(afterRequest);
    });

    test('GET /api/admin returns admin information', async () => {
        const response = await request(server)
            .get('/api/admin')
            .expect(200)
            .expect('Content-Type', /json/);

        expect(response.body.role).toBe('admin');
        expect(response.body.secret)
            .toBe('super-secret-production-key-12345');
    });

    test('GET /api/redirect redirects to a local path', async () => {
        const response = await request(server)
            .get('/api/redirect')
            .query({
                url: '/api/current_time'
            })
            .expect(302);

        expect(response.headers.location)
            .toBe('/api/current_time');
    });

    test.each([
        ['absolute URL', 'https://evil.example'],
        ['protocol-relative URL', '//evil.example'],
        ['backslash trick', '/\\evil.example'],
        ['tab trick (browser strips it)', '/\t/evil.example'],
        ['javascript: URL', 'javascript:alert(1)'],
        ['relative path without leading slash', 'evil.example']
    ])('GET /api/redirect rejects %s (no open redirect)', async (_name, target) => {
        const response = await request(server)
            .get('/api/redirect')
            .query({
                url: target
            })
            .expect(400)
            .expect('Content-Type', /json/);

        expect(response.headers.location).toBeUndefined();
        expect(response.body).toEqual({
            error: 'Only local redirect targets are allowed'
        });
    });

    test('GET /api/redirect without url returns 400', async () => {
        await request(server)
            .get('/api/redirect')
            .expect(400);
    });

    test('GET /api/file returns 500 for missing file', async () => {
        const response = await request(server)
            .get('/api/file')
            .query({
                name: 'does-not-exist.txt'
            })
            .expect(500)
            .expect('Content-Type', /json/);

        expect(response.body).toHaveProperty('error');
        expect(response.body).toHaveProperty('stack');
    });

    test('GET /api/file returns file contents as plain text', async () => {
        const readFileSpy = jest.spyOn(fs, 'readFile')
            .mockImplementation((path, encoding, callback) => {
                callback(null, 'hello from file');
            });

        const response = await request(server)
            .get('/api/file')
            .query({
                name: 'test.txt'
            })
            .expect(200)
            .expect('Content-Type', /text\/plain/);

        expect(response.text).toBe('hello from file');
        expect(readFileSpy).toHaveBeenCalledWith(
            './files/test.txt',
            'utf8',
            expect.any(Function)
        );
    });

    test('GET /api/ping returns combined stdout and stderr', async () => {
        execFile.mockImplementation((file, args, callback) => {
            callback(null, 'PING localhost ok\n', 'some warning\n');
        });

        const response = await request(server)
            .get('/api/ping')
            .query({
                host: 'localhost'
            })
            .expect(200)
            .expect('Content-Type', /text\/plain/);

        expect(response.text).toBe('PING localhost ok\nsome warning\n');

        // No shell: ping is run directly, host is a separate argument.
        expect(execFile).toHaveBeenCalledWith(
            'ping',
            ['-c', '1', '--', 'localhost'],
            expect.any(Function)
        );
    });

    test.each([
        'example.com',
        '192.168.1.10',
        '::1',
        'my-host.internal'
    ])('GET /api/ping accepts host %s', async (host) => {
        execFile.mockImplementation((file, args, callback) => {
            callback(null, 'ok', '');
        });

        await request(server)
            .get('/api/ping')
            .query({ host })
            .expect(200);

        expect(execFile).toHaveBeenCalledWith(
            'ping',
            ['-c', '1', '--', host],
            expect.any(Function)
        );
    });

    test.each([
        ['shell separator', 'localhost; cat /etc/passwd'],
        ['pipe', '|nslookup attacker.example'],
        ['command substitution', '$(id)'],
        ['backticks', '`id`'],
        ['space / extra argument', 'localhost -f'],
        ['option injection', '-f'],
        ['missing host', undefined],
        ['too long', 'a'.repeat(254)]
    ])('GET /api/ping rejects %s (no command injection)', async (_name, host) => {
        const response = await request(server)
            .get('/api/ping')
            .query(host === undefined ? {} : { host })
            .expect(400)
            .expect('Content-Type', /json/);

        expect(response.body).toEqual({ error: 'Invalid host' });
        expect(execFile).not.toHaveBeenCalled();
    });

    test('non-GET request to a known path returns 404', async () => {
        await request(server)
            .post('/api/admin')
            .expect(404)
            .expect('Content-Type', /json/);
    });

    describe('GET /api/token', () => {
        // A fresh key pair per test run - no key is stored anywhere.
        const { privateKey, publicKey } = crypto.generateKeyPairSync('rsa', {
            modulusLength: 2048,
            privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
            publicKeyEncoding: { type: 'spki', format: 'pem' }
        });

        const originalKey = process.env.TOKEN_SIGNING_KEY;

        beforeEach(() => {
            process.env.TOKEN_SIGNING_KEY = privateKey;
        });

        afterAll(() => {
            if (originalKey === undefined) {
                delete process.env.TOKEN_SIGNING_KEY;
            } else {
                process.env.TOKEN_SIGNING_KEY = originalKey;
            }
        });

        const verify = (token) => {
            const [payload, signature] = token.split('.');

            return crypto.verify(
                'sha256',
                Buffer.from(payload),
                publicKey,
                Buffer.from(signature, 'base64url')
            );
        };

        test('returns a token signed with the key from the environment', async () => {
            const response = await request(server)
                .get('/api/token')
                .query({
                    user: 'alice'
                })
                .expect(200)
                .expect('Content-Type', /json/);

            const [payload] = response.body.token.split('.');

            expect(JSON.parse(decodeURIComponent(payload)).sub).toBe('alice');
            expect(verify(response.body.token)).toBe(true);
        });

        test('defaults to anonymous user', async () => {
            const response = await request(server)
                .get('/api/token')
                .expect(200);

            const [payload] = response.body.token.split('.');

            expect(JSON.parse(decodeURIComponent(payload)).sub).toBe('anonymous');
        });

        test('accepts a single-line key with escaped \\n', async () => {
            process.env.TOKEN_SIGNING_KEY = privateKey.replace(/\n/g, '\\n');

            const response = await request(server)
                .get('/api/token')
                .expect(200);

            expect(verify(response.body.token)).toBe(true);
        });

        test('returns 503 without leaking details when the key is missing', async () => {
            delete process.env.TOKEN_SIGNING_KEY;
            jest.spyOn(console, 'error').mockImplementation(() => {});

            const response = await request(server)
                .get('/api/token')
                .expect(503)
                .expect('Content-Type', /json/);

            expect(response.body).toEqual({
                error: 'Token signing is not configured'
            });
            expect(console.error).toHaveBeenCalled();
        });
    });

    test('GET /api/greeting greets the supplied name', async () => {
        const response = await request(server)
            .get('/api/greeting')
            .query({
                name: 'Alice'
            })
            .expect(200)
            .expect('Content-Type', /text\/plain/);

        expect(response.text).toBe('Hello, Alice!');
    });

    test('GET /api/greeting defaults to stranger', async () => {
        const response = await request(server)
            .get('/api/greeting')
            .expect(200);

        expect(response.text).toBe('Hello, stranger!');
    });

    test('GET /api/greeting does not execute template code in name', async () => {
        const response = await request(server)
            .get('/api/greeting')
            .query({
                name: '<%= 7 * 7 %>'
            })
            .expect(200);

        // Printed (escaped) as text, never evaluated.
        expect(response.text).toBe('Hello, &lt;%= 7 * 7 %&gt;!');
    });

    test('GET /api/greeting does not run injected code (no RCE)', async () => {
        const response = await request(server)
            .get('/api/greeting')
            .query({
                name: '<% global.pwned = true %>${process.exit(1)}'
            })
            .expect(200);

        expect(global.pwned).toBeUndefined();
        expect(response.text).toContain('${process.exit(1)}');
    });

    test('GET /api/greeting handles input that is not a valid template', async () => {
        const response = await request(server)
            .get('/api/greeting')
            .query({
                name: '<%= ) %>'
            })
            .expect(200);

        expect(response.text).toBe('Hello, &lt;%= ) %&gt;!');
    });

    describe('malformed input does not crash the server (DoS)', () => {
        beforeEach(() => {
            jest.spyOn(console, 'error').mockImplementation(() => {});
        });

        test('null byte in file name returns 400', async () => {
            const response = await request(server)
                .get('/api/file?name=test.txt%00x')
                .expect(400)
                .expect('Content-Type', /json/);

            expect(response.body).toEqual({ error: 'Bad request' });
            expect(console.error).toHaveBeenCalled();
        });

        test('null byte in ping host returns 400', async () => {
            const response = await request(server)
                .get('/api/ping?host=localhost%00x')
                .expect(400);

            expect(response.body).toEqual({ error: 'Invalid host' });
            expect(execFile).not.toHaveBeenCalled();
        });

        test('CRLF in redirect URL returns 400 (no header injection)', async () => {
            const response = await request(server)
                .get('/api/redirect?url=/home%0D%0ASet-Cookie:x=1')
                .expect(400);

            // Rejected by isSafeRedirect before any header is written.
            expect(response.headers['set-cookie']).toBeUndefined();
            expect(response.body).toEqual({
                error: 'Only local redirect targets are allowed'
            });
        });

        test('server keeps answering after a malformed request', async () => {
            await request(server).get('/api/file?name=%00').expect(400);
            await request(server).get('/api/current_time').expect(200);
        });

        test('destroys the socket if headers were already sent', () => {
            const res = {
                headersSent: true,
                destroy: jest.fn(),
                writeHead: jest.fn()
            };
            const req = { method: 'GET', url: '/api/current_time' };

            // Force a throw after "headers were sent".
            res.end = () => { throw new Error('boom'); };

            requestHandler(req, res);

            expect(res.destroy).toHaveBeenCalled();
        });
    });

    // ==========================================================
    // PROPERTY-BASED TESTS (fast-check)
    // Instead of a few hand-picked inputs, fast-check generates
    // thousands of random strings (including unicode, control and
    // shell characters) and checks a rule that must always hold.
    // ==========================================================
    describe('input validators (property-based)', () => {
        const SHELL_OR_SPACE = /[\s;|&$`'"<>(){}[\]\\*?!#~%^=,\0]/;

        test('isValidHost never accepts shell characters, spaces or a leading "-"', () => {
            fc.assert(fc.property(fc.string({ unit: 'binary' }), (host) => {
                if (isValidHost(host)) {
                    expect(host).not.toMatch(SHELL_OR_SPACE);
                    expect(host.startsWith('-')).toBe(false);
                    expect(host.length).toBeLessThanOrEqual(253);
                }
            }), { numRuns: 5000 });
        });

        test('isValidHost accepts every generated domain name and IP address', () => {
            fc.assert(fc.property(
                fc.oneof(fc.domain(), fc.ipV4(), fc.ipV6()),
                (host) => {
                    expect(isValidHost(host)).toBe(true);
                }
            ), { numRuns: 2000 });
        });

        test('isSafeRedirect only accepts targets that stay on the same origin', () => {
            const origin = 'http://app.example';

            fc.assert(fc.property(
                fc.oneof(
                    fc.string({ unit: 'binary' }),
                    // Short strings from the characters that matter for
                    // URL parsing, so tricky combinations are found fast.
                    fc.array(
                        fc.constantFrom('/', '\\', '\t', '\n', '\r', ' ', '\u0000', 'a', '.', ':', '@', '%', '?', '#'),
                        { maxLength: 8 }
                    ).map((chars) => chars.join('')),
                    fc.webUrl(),
                    fc.string().map((s) => '/' + s),
                    fc.string().map((s) => '//' + s),
                    fc.string().map((s) => '/\\' + s)
                ),
                (target) => {
                    if (isSafeRedirect(target)) {
                        // How a browser resolves the Location header.
                        expect(new URL(target, origin + '/api/redirect').origin).toBe(origin);
                    }
                }
            ), { numRuns: 5000 });
        });

        test('isSafeRedirect: no "/" + whitespace/control trick escapes the origin', () => {
            // Browsers strip tab / CR / LF from URLs, so "/\t/evil.com"
            // becomes "//evil.com" (another site). This found that bypass.
            const origin = 'http://app.example';

            fc.assert(fc.property(
                fc.array(
                    fc.constantFrom('/', '\\', '\t', '\n', '\r', ' ', '\u0000', '\u000b', '\u000c', 'a', '.', ':', '@'),
                    { minLength: 1, maxLength: 6 }
                ).map((chars) => '/' + chars.join('')),
                (target) => {
                    if (isSafeRedirect(target)) {
                        expect(new URL(target, origin + '/api/redirect').origin).toBe(origin);
                    }
                }
            ), { numRuns: 10000 });
        });

        test('isSafeRedirect accepts every local path', () => {
            fc.assert(fc.property(
                fc.webPath().filter((p) => p.startsWith('/') && !/^\/[/\\]/.test(p)),
                (path) => {
                    expect(isSafeRedirect(path)).toBe(true);
                }
            ), { numRuns: 2000 });
        });
    });

    test('unknown endpoint returns 404', async () => {
        const response = await request(server)
            .get('/api/does-not-exist')
            .expect(404)
            .expect('Content-Type', /json/);

        expect(response.body).toEqual({
            error: 'Not found'
        });
    });

});