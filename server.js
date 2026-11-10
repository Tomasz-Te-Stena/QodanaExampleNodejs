const http = require('http');
const fs = require('fs');
const { exec } = require('child_process');
const url = require('url');
const crypto = require('crypto');
const { Buffer } = require('buffer');

// SECURITY ERROR #8: Vulnerable dependency.
// lodash 4.17.20 is pinned on purpose: CVE-2021-23337 (HIGH),
// command injection via _.template. Fixed in 4.17.21.
// Detected by: Trivy SCA (trivy fs / trivy image --scanners vuln).
const _ = require('lodash');

// INTENTIONALLY INSECURE CODE.
// Training / security pipeline testing only.

// SECURITY ERROR #1: Hard-coded secret
const API_SECRET = 'super-secret-production-key-12345';

// SECURITY ERROR #7: Hard-coded private key.
// Throwaway RSA key generated only for this demo - not used anywhere.
// Detected by: Trivy secret scan (trivy fs / trivy image --scanners secret).
const TOKEN_SIGNING_KEY = `-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDGrRR3KDH/Lvpx
lnDue+QI+gTXc8713zZbzitqgT2wsdFNvS/NsSS4GkYnkJPg81wX+GE8tW0QtvDV
P3oTrmD5XAE9Xk9/QctJ2L07mNzSeu0vQHAZcD6FoPcjVf21eDJF9Z3G+SWH5/nQ
qbKrRwxOwHym0kaSY4wnl2CwjerkQcH4PTKfu0OIbbezP1n8gfUDMF7r0B8/Eupl
6jVw3eRIwzOzWt0NIwDhsv6CJPp1OQfBo5Q15UpD2v4zbKWvBtIgljtJ2/+Qxzth
WHLOal9fDWmFVE1UD0McyZSE+5evQcdl3ynrgRGhqRHI5EcyEGjtBThwvK/iT3KU
n7PG6FFXAgMBAAECggEAA+arHl8uLXi31y92iTWVN9iSQW7B3hG4yLBcKYu0cTnp
8QZUICGoexWc/LLkjHK1g2JPpSME1g1ZiOkQVb7t+DImc2oyJ76xe1eOTlNv5pFz
rc1XRiXuPFkkRnqDmvgWDfScLqd+uqlDPlB5XyPr1HIIII3EGqS/au7t1ERScT07
xu3Vl44vi1C1R7TxPaT3iOiLMLsBrZdX1Y1j06PBlJ9qXUlK8PluHWcwtte/a3rp
FOG18BP0iRHLPH2VrzwUFLp6XGr0FgAZtVVSC/fhk3bi4bM0Qk+TuiunRHCmZWpQ
QvuP67lJdieopO/Id5prlOcl2DlOMPrljVmEZlG/rQKBgQDomvNck1JC6ZeZ9YO1
BwCMztGZBa8SId+1ssYBNWWLGVmUpOQSP76xjstwPwVzCbBw0iNMtC8kSwhTN+Qs
wBmnVEV4uULrv6Wa3YlbeIdL/h+KRMYASPhqWriajiHIE+Lv6lCLJDt6/UnZmEso
1XfeBuLhpGy47tJ2j6O1vABU9QKBgQDaqIf3hm+/GnWUQj9rBIRjfO8Mu4zkz0dH
wJdpxh0Gc3u6K+AmoBe78amhJ5xo53B5AOqUzY+ylUFZZQF9xuM5Su2BXfjVBywY
lk3wHtQlg0DkmziqkweWVHEs37DlPrkf1k7QQc83djpByUOpJL/2Ol8yrufv3Xzx
5BRYhoy9mwKBgE4r7Qe6txWnvXxPZ5EKJmQsCYK8x0Z3veApkaPMVzD1Nwbel4uO
gr7Xd4VkmKc9pV91L8nScFlpIgYdrYBgmv6CMsrMsDHceYJfW48zJX0jjWQBku17
mIjdrla6152PGWB5xdHNPnQp9Yy8Qt4ZR6yFcfBVOvi3wmF4CpPD9/SVAoGAdts1
TW9ePtr7HuQD5QBHlmzK5HjuVVH2xSIDLBPsox0THFfNODG9tQPf2SHW+48SrDO7
T7eNbN2E8DrfXKdHzFTWVYPnRqTna1YId4XKe7mlBJ77Zn0Vmrm761CMr5AwwQWV
Qc8D/HnfoPLuPHslfYqtRLeei9wxlqsMBDLfPhECgYEAwJXSeC9N70QDgo4DlDw/
zxUnXPtsBlNBHBUUOs8TQUMmUx6tvGzNAIKgjQsGAETxjvdswC9CpErjvLAITo0I
Xthkyh2ZnxTOeXWcn7nl/ftnBULYaC2gn4bqDbfv3hEe51+qvkcIG3PUmJo3mZDe
nlBT0lj6NLyD1ri6v6jj49M=
-----END PRIVATE KEY-----`;

// Signs "<payload>.<signature>" with the hard-coded key above.
function signToken(username) {
    const payload = JSON.stringify({ sub: username, iat: Date.now() });
    const encoded = encodeURIComponent(payload);
    const signature = crypto
        .sign('sha256', Buffer.from(encoded), TOKEN_SIGNING_KEY)
        .toString('base64url');

    return encoded + '.' + signature;
}

// Renders a greeting with lodash.template.
function renderGreeting(name) {
    // SECURITY ERROR #9: Template injection - user input is compiled
    // as a lodash template, so "<%= ... %>" in the name runs code.
    const compiled = _.template('Hello, ' + name + '!');
    return compiled({});
}

function requestHandler(req, res) {
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
        res.writeHead(200, {
            'Content-Type': 'application/json'
        });

        return res.end(JSON.stringify({
            token: signToken(query.user || 'anonymous')
        }));
    }

    // GET /api/greeting?name=Alice
    if (req.method === 'GET' && path === '/api/greeting') {
        try {
            const text = renderGreeting(query.name || 'stranger');

            res.writeHead(200, {
                'Content-Type': 'text/plain'
            });

            return res.end(text);
        } catch (err) {
            res.writeHead(400, {
                'Content-Type': 'application/json'
            });

            return res.end(JSON.stringify({
                error: err.message
            }));
        }
    }

    // GET /api/redirect?url=https://example.com
    if (req.method === 'GET' && path === '/api/redirect') {
        // SECURITY ERROR #6: Open redirect
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