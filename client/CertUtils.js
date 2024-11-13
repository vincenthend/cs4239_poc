const forge = require('node-forge')
const path = require('node:path')
const fs = require('fs-extra')

class CertUtils {
    static _getRootPKPair(options) {
        const { outputPath } = options

        const rootCertPath = path.resolve(outputPath, './root.cert.pem')
        const rootPublicKeyPath = path.resolve(outputPath, './root.key.pub')
        const rootPrivateKeyPath = path.resolve(outputPath, './root.key.pem')

        const certMissing = !fs.existsSync(rootPrivateKeyPath) ||
            !fs.existsSync(rootCertPath) ||
            !fs.existsSync(rootPublicKeyPath) || options.clear

        if (certMissing) {
            const pair = forge.pki.rsa.generateKeyPair(2048)
            const rootCert = forge.pki.createCertificate()
            rootCert.publicKey = pair.publicKey
            rootCert.serialNumber = '01'
            rootCert.validity.notBefore = new Date()
            rootCert.validity.notAfter = new Date()
            rootCert.validity.notAfter.setFullYear(rootCert.validity.notBefore.getFullYear() + 5)

            rootCert.setSubject([
                { name: 'countryName', value: 'SG' },
                { name: 'commonName', value: 'Cert Common Name' }
            ])
            rootCert.setIssuer([
                { name: 'countryName', value: 'SG' },
                { name: 'commonName', value: 'Cert Common Name' }
            ])

            rootCert.setExtensions([
                {
                    name: 'basicConstraints',
                    cA: true
                },
                {
                    name: 'subjectKeyIdentifier'
                },
                {
                    name: 'authorityKeyIdentifier'
                }
            ])

            rootCert.sign(pair.privateKey, forge.md.sha256.create())

            fs.ensureDirSync(path.resolve(process.cwd(), outputPath))
            fs.writeFileSync(rootCertPath, forge.pki.certificateToPem(rootCert))
            fs.writeFileSync(rootPublicKeyPath, forge.pki.publicKeyToPem(pair.publicKey))
            fs.writeFileSync(rootPrivateKeyPath, forge.pki.privateKeyToPem(pair.privateKey))
            return { cert: rootCert, publicKey: pair.publicKey, privateKey: pair.privateKey }
        }

        return {
            publicKey: forge.pki.publicKeyFromPem(fs.readFileSync(rootPublicKeyPath, 'utf8')),
            privateKey: forge.pki.privateKeyFromPem(fs.readFileSync(rootPrivateKeyPath, 'utf8')),
            cert: forge.pki.certificateFromPem(fs.readFileSync(rootCertPath, 'utf8'))
        }
    }

    static _generateDomainCert(rootCA, options) {
        const privateCAKey = rootCA.privateKey
        const keys = forge.pki.rsa.generateKeyPair(2048)
        const cert = forge.pki.createCertificate()
        cert.publicKey = keys.publicKey
        cert.serialNumber = '01'
        cert.validity.notBefore = new Date()
        cert.validity.notAfter = new Date()
        cert.validity.notAfter.setFullYear(cert.validity.notBefore.getFullYear() + 1)

        const attrsSubject = [
            {
                name: 'commonName',
                value: options.domain
            },
            {
                name: 'organizationName',
                value: 'local'
            }
        ]
        cert.setSubject(attrsSubject)
        cert.setIssuer(rootCA.cert.subject.attributes)
        cert.setExtensions([
            {
                name: 'keyUsage',
                keyCertSign: true,
                digitalSignature: true,
                nonRepudiation: true,
                keyEncipherment: true,
                dataEncipherment: true
            },
            {
                name: 'subjectAltName',
                altNames: [
                    {
                        type: 2, // URI
                        value: options.domain
                    }
                ]
            }
        ])

        cert.sign(privateCAKey, forge.md.sha256.create())

        // PEM-format keys and cert
        return {
            root: rootCA,
            privateKey: forge.pki.privateKeyToPem(keys.privateKey),
            publicKey: forge.pki.publicKeyToPem(keys.publicKey),
            certificate: forge.pki.certificateToPem(cert)
        }
    }

    static generateCert(options = { outputPath: './cert', domain: 'localhost' }) {
        const pair = this._getRootPKPair(options)
        return this._generateDomainCert(pair, options)
    }
}

module.exports = CertUtils