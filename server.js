const http = require('http');
const fs = require('fs');
const { exec } = require('child_process');
const url = require('url');

// INTENTIONALLY INSECURE CODE.
// Training / security pipeline testing only.

// SECURITY ERROR #1: Hard-coded secret
const API_SECRET = 'super-secret-production-key-12345';

http.createServer((req, res) => {
    const parsedUrl = url.parse(req.url, true);
    const path = parsedUrl.pathname;
    const query = parsedUrl.query;

    // GET /api/hello
    if (req.method === 'GET' && path === '/api/hello') {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        return res.end(JSON.stringify({
            message: 'Hello World!'
        }));
    }

    // GET /api/file?name=test.txt
    if (req.method === 'GET' && path === '/api/file') {

        // SECURITY ERROR #2:
        // Path traversal / arbitrary file read.
        const filename = query.name;

        fs.readFile('./files/' + filename, 'utf8', (err, data) => {
            if (err) {
                res.writeHead(500, {
                    'Content-Type': 'application/json'
                });

                // SECURITY ERROR #3:
                // Internal error information disclosure.
                return res.end(JSON.stringify({
                    error: err.message,
                    stack: err.stack
                }));
            }

            res.writeHead(200, {
                'Content-Type': 'text/plain'
            });

            return res.end(data);
        });

        return;
    }

    // GET /api/ping?host=localhost
    if (req.method === 'GET' && path === '/api/ping') {

        const host = query.host;

        // SECURITY ERROR #4:
        // Command injection.
        exec('ping -c 1 ' + host, (error, stdout, stderr) => {
            res.writeHead(200, {
                'Content-Type': 'text/plain'
            });

            res.end(stdout + stderr);
        });

        return;
    }

    // GET /api/admin
    if (req.method === 'GET' && path === '/api/admin') {

        // SECURITY ERROR #5:
        // Sensitive endpoint without authentication/authorization.
        res.writeHead(200, {
            'Content-Type': 'application/json'
        });

        return res.end(JSON.stringify({
            role: 'admin',
            secret: API_SECRET
        }));
    }

    // GET /api/redirect?url=https://example.com
    if (req.method === 'GET' && path === '/api/redirect') {

        // SECURITY ERROR #6:
        // Unvalidated redirect.
        res.writeHead(302, {
            Location: query.url
        });

        return res.end();
    }

    res.writeHead(404, {
        'Content-Type': 'application/json'
    });

    res.end(JSON.stringify({
        error: 'Not found'
    }));

}).listen(8080, () => {
    console.log('Vulnerable REST API listening on port 8080');
});