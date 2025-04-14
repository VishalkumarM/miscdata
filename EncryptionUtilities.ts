import * as forge from 'node-forge';

export class EncryptionUtilities {

    pubKey: string;
    privKey: string;

    constructor(pPublicKey, pPrivateKey) {
        this.pubKey = null;
        this.privKey = null;
        if (pPublicKey != null) {
            if (pPublicKey.indexOf("BEGIN PUBLIC KEY") < 0) {
                pPublicKey = "-----BEGIN PUBLIC KEY-----" + pPublicKey + "-----END PUBLIC KEY-----"
            }
            this.pubKey = forge.pki.publicKeyFromPem(pPublicKey);
        }

        if (pPrivateKey != null) {
            if (pPrivateKey.indexOf("BEGIN PRIVATE KEY") < 0) {
                pPrivateKey = "-----BEGIN PRIVATE KEY-----" + pPrivateKey + "-----END PRIVATE KEY-----"
            }
            this.privKey = forge.pki.privateKeyFromPem(pPrivateKey);
        }
    }

    encryptWithPublic = function (pData) {
        var encoded = this.pubKey.encrypt(pData);
        return forge.util.encode64(encoded);
    }

    decryptWithPublic = function (pData) {
        var decoded = forge.pki.rsa.decrypt(pData, this.pubKey, true, true);
        return decoded;
    }

    encryptWithPrivate = function (pData) {
        var response = forge.pki.rsa.encrypt(pData, this.privKey, 0x01);
        return forge.util.encode64(response);
    }

    decryptWithPrivate = function (pData) {
        var decoded = forge.pki.rsa.decrypt(pData, this.privKey, false, true);
        return decoded;
    }

    sign = function (pData, pType?) {
        var md = forge.md.sha256.create();
        let lType = (pType == null) ? 'utf8' : pType;
        if (lType == 'raw') {
            md.update(pData);
        } else {
            md.update(pData, lType);
        }     
        var signature = this.privKey.sign(md);
        return forge.util.encode64(signature);
    }

    verify = function (pData, pSignature, pType?) {
        var lSignBytes = forge.util.decode64(pSignature);
        var md = forge.md.sha256.create();
        let lType = (pType == null) ? 'utf8' : pType;
        if (lType == 'raw') {
            md.update(pData);
        } else {
            md.update(pData, lType);
        }
        var verified = this.pubKey.verify(md.digest().bytes(), lSignBytes);
        return verified;
    }

    doMD5 = function (pData) {
        var md = forge.md.md5.create();
        md.update(pData);
        var lMDHex = md.digest().toHex();
        return lMDHex;
    }

    base64Decode = function (pData) {
        return forge.util.decode64(pData);
    }

    base64Encode = function (pData) {
        return forge.util.encode64(pData);
    }
    /**
     * Encryption AES256
     * pPassphrase : encrypt passphrase
     * pData : data to be encrypted
     * 
     * return {passphrase: "salt.iv.passphrase", data : "encrypted data base 64 encoded"}
     */
    encryptAES = function (pPassphrase: string, pData: string): { passphrase: string, data: string } {
        let keySize = 256;
        let salt = forge.random.getBytes(16);
        let iv = forge.random.getBytes(16);
        let key = forge.pkcs5.pbkdf2(pPassphrase, salt, 1000, 32);
        let input = forge.util.createBuffer(pData, 'utf8');
        let cipher = forge.cipher.createCipher('AES-CBC', key);
        cipher.start({ iv: iv });
        cipher.update(input);
        cipher.finish();
        let ciphertext = cipher.output.getBytes();
        let ciphertext64 = forge.util.encode64(ciphertext);
        let lIvStr = forge.util.binary.hex.encode(iv);
        let lSaltStr = forge.util.binary.hex.encode(salt);
        return { passphrase: lSaltStr + "." + lIvStr + "." + pPassphrase, data: ciphertext64 };
    }
    /**
     * Decryption AES256
     * pPassphrase : salt.iv.passphrase
     * pData : data to be decrypted base 64 encoded
     * 
     * return decrypted data
     */
    decryptAES = function (pPassphrase: string, pData: string): string {
        let lPassPhraseParts: Array<string> = pPassphrase.split(".");
        let lTmpSalt = forge.util.hexToBytes(lPassPhraseParts[0]);
        let lTmpIv = forge.util.hexToBytes(lPassPhraseParts[1]);
        let ciphertext = forge.util.decode64(pData);
        let input = forge.util.createBuffer(ciphertext);
        let key = forge.pkcs5.pbkdf2(lPassPhraseParts[2], lTmpSalt, 1000, 32);
        let decipher = forge.cipher.createDecipher('AES-CBC', key);
        decipher.start({ iv: lTmpIv });
        decipher.update(input);
        decipher.finish();
        return decipher.output.toString('utf8');
    }
}