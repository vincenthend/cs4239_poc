const https = require('https');
const fs = require('fs');
const CertUtils = require('./CertUtils');

const hostname = process.env.HOSTNAME || '0.0.0.0';
const port = process.env.PORT || 3000;

const cert = CertUtils.generateCert()

const options = {
    ca: cert.root.certificate,
    cert: cert.certificate,
    key: cert.privateKey,
    rejectUnauthorized: true,
    requestCert: true,
};

const server = https.createServer(options, (req, res) => {
    res.statusCode = 200;
    res.setHeader('Content-Type', 'text/plain');
    res.end('Hello World\n');
});

server.listen(port, hostname, () => {
    console.log(`Server running at https://${hostname}:${port}/`);
});

