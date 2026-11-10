const request = require('supertest');
const http = require('http');

const { requestHandler } = require('./server');

describe('Vulnerable REST API', () => {

    const server = http.createServer(requestHandler);

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