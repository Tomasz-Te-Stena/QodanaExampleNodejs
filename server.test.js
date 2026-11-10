// server.js destructures exec at load time, so it must be mocked
// before server.js is required. No real shell command ever runs.
jest.mock('child_process', () => ({
    ...jest.requireActual('child_process'),
    exec: jest.fn()
}));

const request = require('supertest');
const http = require('http');
const fs = require('fs');
const crypto = require('crypto');
const { Buffer } = require('buffer');
const { exec } = require('child_process');

const { requestHandler } = require('./server');

describe('Vulnerable REST API', () => {

    const server = http.createServer(requestHandler);

    afterEach(() => {
        jest.restoreAllMocks();
        exec.mockReset();
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
        exec.mockImplementation((command, callback) => {
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
        expect(exec).toHaveBeenCalledWith(
            'ping -c 1 localhost',
            expect.any(Function)
        );
    });

    test('GET /api/ping passes host unsanitised to the shell (command injection)', async () => {
        exec.mockImplementation((command, callback) => {
            callback(null, '', '');
        });

        await request(server)
            .get('/api/ping')
            .query({
                host: 'localhost; cat /etc/passwd'
            })
            .expect(200);

        // Documents the intentional vulnerability: input reaches exec as-is.
        expect(exec).toHaveBeenCalledWith(
            'ping -c 1 localhost; cat /etc/passwd',
            expect.any(Function)
        );
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
            // The real exec throws synchronously on null bytes.
            exec.mockImplementation(() => {
                const err = new TypeError('command must not contain null bytes');
                err.code = 'ERR_INVALID_ARG_VALUE';
                throw err;
            });

            const response = await request(server)
                .get('/api/ping?host=localhost%00x')
                .expect(400);

            expect(response.body).toEqual({ error: 'Bad request' });
        });

        test('CRLF in redirect URL returns 400 (no header injection)', async () => {
            const response = await request(server)
                .get('/api/redirect?url=/home%0D%0ASet-Cookie:x=1')
                .expect(400);

            expect(response.headers['set-cookie']).toBeUndefined();
            expect(response.body).toEqual({ error: 'Bad request' });
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