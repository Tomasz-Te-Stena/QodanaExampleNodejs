const http = require('http');
const fs = require('fs');
const { exec } = require('child_process');
const url = require('url');
const crypto = require('crypto');
const { Buffer } = require('buffer');

// FIXED (was SECURITY ERROR #8: lodash 4.17.20, CVE-2021-23337).
// lodash is now ^4.18.1; Trivy SCA (trivy fs / trivy image) checks it.
const _ = require('lodash');

// INTENTIONALLY INSECURE CODE.
// Training / security pipeline testing only.

// SECURITY ERROR #1: Hard-coded secret
const API_SECRET = 'super-secret-production-key-12345';

// FIXED (was SECURITY ERROR #7: hard-coded private key).
// The signing key is no longer in the source code. It is read at
// runtime from the TOKEN_SIGNING_KEY environment variable (a PEM
// private key; "\n" escapes are accepted so it fits in one line,
// e.g. an Azure DevOps secret variable or a Docker/K8s secret).
function getSigningKey() {
    const pem = process.env.TOKEN_SIGNING_KEY;

    if (!pem) {
        throw new Error('TOKEN_SIGNING_KEY environment variable is not set');
    }

    return pem.replace(/\\n/g, '\n');
}

// Signs "<payload>.<signature>" with the key from the environment.
function signToken(username) {
    const payload = JSON.stringify({ sub: username, iat: Date.now() });
    const encoded = encodeURIComponent(payload);
    const signature = crypto
        .sign('sha256', Buffer.from(encoded), getSigningKey())
        .toString('base64url');

    return encoded + '.' + signature;
}

// FIXED (was SECURITY ERROR #9: template injection / RCE).
// The template is a constant, compiled once. User input is only
// passed in as data and escaped by "<%- %>", so "<%= ... %>" in the
// name is printed as text instead of being executed.
const greetingTemplate = _.template('Hello, <%- name %>!');

function renderGreeting(name) {
    return greetingTemplate({ name: String(name) });
}

// FIXED (was SECURITY ERROR #6: open redirect).
// Only local paths are allowed: "/something", but not "//host" or
// "/\host", which browsers treat as a different site.
function isSafeRedirect(target) {
    return typeof target === 'string' && /^\/(?![/\\])/.test(target);
}

// Entry point for every request. Some Node APIs used below throw
// synchronously on malformed input (fs.readFile / exec reject null
// bytes, res.writeHead rejects CR/LF in header values). Without this
// guard one such request (e.g. ?name=a%00b) crashed the whole process,
// a denial of service found by the Nuclei DAST scan. The intentional
// vulnerabilities below are unchanged; only the crash is fixed.
function requestHandler(req, res) {
    try {
        return handleRequest(req, res);
    } catch (err) {
        console.error('Rejected malformed request:', err.code || err.message);

        if (res.headersSent) {
            return res.destroy();
        }

        res.writeHead(400, {
            'Content-Type': 'application/json'
        });

        return res.end(JSON.stringify({
            error: 'Bad request'
        }));
    }
}

function handleRequest(req, res) {
    const parsedUrl = url.parse(req.url, true);
    const path = parsedUrl.pathname;
    const query = parsedUrl.query;

    // GET /api/current_time
    if (req.method === 'GET' && path === '/api/current_time') {
        res.writeHead(200, {
            'Content-Type': 'application/json'
        });

        return res.end(JSON.stringify({
            currentTime: new Date().toISOString()
        }));
    }

    // GET /api/file?name=test.txt
    if (req.method === 'GET' && path === '/api/file') {
        const filename = query.name;

        // SECURITY ERROR #2: Path traversal
        fs.readFile('./files/' + filename, 'utf8', (err, data) => {
            if (err) {
                res.writeHead(500, {
                    'Content-Type': 'application/json'
                });

                // SECURITY ERROR #3: Information disclosure
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

        // SECURITY ERROR #4: Command injection
        exec('ping -c 1 ' + host, (error, stdout, stderr) => {
            res.writeHead(200, {
                'Content-Type': 'text/plain'
            });

            return res.end(stdout + stderr);
        });

        return;
    }

    // GET /api/admin
    if (req.method === 'GET' && path === '/api/admin') {
        // SECURITY ERROR #5: No authentication/authorization
        res.writeHead(200, {
            'Content-Type': 'application/json'
        });

        return res.end(JSON.stringify({
            role: 'admin',
            secret: API_SECRET
        }));
    }

    // GET /api/token?user=alice
    if (req.method === 'GET' && path === '/api/token') {
        let token;

        try {
            token = signToken(query.user || 'anonymous');
        } catch (err) {
            // Missing / invalid key: report it without leaking details.
            console.error('Token signing failed:', err.message);

            res.writeHead(503, {
                'Content-Type': 'application/json'
            });

            return res.end(JSON.stringify({
                error: 'Token signing is not configured'
            }));
        }

        res.writeHead(200, {
            'Content-Type': 'application/json'
        });

        return res.end(JSON.stringify({
            token
        }));
    }

    // GET /api/greeting?name=Alice
    if (req.method === 'GET' && path === '/api/greeting') {
        const text = renderGreeting(query.name || 'stranger');

        res.writeHead(200, {
            'Content-Type': 'text/plain'
        });

        return res.end(text);
    }

    // GET /api/redirect?url=/api/current_time
    if (req.method === 'GET' && path === '/api/redirect') {
        if (!isSafeRedirect(query.url)) {
            res.writeHead(400, {
                'Content-Type': 'application/json'
            });

            return res.end(JSON.stringify({
                error: 'Only local redirect targets are allowed'
            }));
        }

        res.writeHead(302, {
            Location: query.url
        });

        return res.end();
    }

    res.writeHead(404, {
        'Content-Type': 'application/json'
    });

    return res.end(JSON.stringify({
        error: 'Not found'
    }));
}

// Start HTTP server only when running:
// node server.js
if (require.main === module) {
    http.createServer(requestHandler).listen(8080, () => {
        console.log('Vulnerable REST API listening on port 8080');
    });
}

// Jest can import this without starting port 8080.
module.exports = { requestHandler };