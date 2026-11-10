// server.js destructures exec at load time, so it must be mocked
// before server.js is required. No real shell command ever runs.
jest.mock('child_process', () => ({
    ...jest.requireActual('child_process'),
    exec: jest.fn()
}));

const request = require('supertest');
const http = require('http');
const fs = require('fs');
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

    test('GET /api/redirect redirects to supplied URL', async () => {
        const response = await request(server)
            .get('/api/redirect')
            .query({
                url: 'https://example.com'
            })
            .expect(302);

        expect(response.headers.location)
            .toBe('https://example.com');
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

    test('GET /api/token returns a signed token for the user', async () => {
        const response = await request(server)
            .get('/api/token')
            .query({
                user: 'alice'
            })
            .expect(200)
            .expect('Content-Type', /json/);

        const [payload, signature] = response.body.token.split('.');

        expect(JSON.parse(decodeURIComponent(payload)).sub).toBe('alice');
        // RSA-2048 signature, base64url encoded.
        expect(signature).toMatch(/^[A-Za-z0-9_-]{342}$/);
    });

    test('GET /api/token defaults to anonymous user', async () => {
        const response = await request(server)
            .get('/api/token')
            .expect(200);

        const [payload] = response.body.token.split('.');

        expect(JSON.parse(decodeURIComponent(payload)).sub).toBe('anonymous');
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

    test('GET /api/greeting evaluates template code in name (template injection)', async () => {
        const response = await request(server)
            .get('/api/greeting')
            .query({
                name: '<%= 7 * 7 %>'
            })
            .expect(200);

        // Documents the intentional vulnerability: input is executed.
        expect(response.text).toBe('Hello, 49!');
    });

    test('GET /api/greeting returns 400 for an invalid template', async () => {
        const response = await request(server)
            .get('/api/greeting')
            .query({
                name: '<%= ) %>'
            })
            .expect(400)
            .expect('Content-Type', /json/);

        expect(response.body).toHaveProperty('error');
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