import * as crypto from "node:crypto";
import { ec as EC } from 'elliptic';

const ec = new EC('secp256k1');

export class Encryptor {
    /**
     * Encrypts a payload using the recipient's public key.
     *
     * This method generates an ephemeral key pair to derive a shared secret
     * using Elliptic Curve Diffie-Hellman (ECDH). The payload is then encrypted 
     * using AES-256-GCM with the derived shared key, providing confidentiality and
     * authenticity of the message.
     *
     * @param recipientPublicKeyHex - The recipient's public key in hexadecimal format.
     * @param payload - The string payload to be encrypted.
     * @returns An object containing the encrypted payload, IV, authentication tag, and ephemeral public key.
     */
    public static encryptPayload(
        recipientPublicKeyHex: string,
        payload: string
    ){  
        const recipientPublicKey = ec.keyFromPublic(recipientPublicKeyHex, 'hex').getPublic();
        const ephemeralKeyPair = ec.genKeyPair();
        const ephemeralPublicKey = ephemeralKeyPair.getPublic('hex'); 

        const sharedSecret = ephemeralKeyPair.derive(recipientPublicKey);
        const sharedKey = crypto.createHash('sha256').update(sharedSecret.toString(16)).digest();
        const iv = crypto.randomBytes(12);
        const cipher = crypto.createCipheriv('aes-256-gcm', sharedKey, iv);

        const encrypted = Buffer.concat([cipher.update(payload, 'utf8'), cipher.final()]);
        const authTag = cipher.getAuthTag(); 

        return {
            payload: '0x' + encrypted.toString('hex'),
            iv: '0x' + iv.toString('hex'),
            authTag: '0x' + authTag.toString('hex'),
            ephemeralPublicKey: '0x' + ephemeralPublicKey
        };
    }

    /**
     * Decrypts an encrypted payload using the recipient's private key.
     *
     * This method derives the shared secret using the recipient's private key and
     * the sender's ephemeral public key. The derived shared key is then used to
     * decrypt the payload using AES-256-GCM, ensuring confidentiality and integrity.
     *
     * @param recipientPrivateKeyHex - The recipient's private key in hexadecimal format.
     * @param encryptedData - An object containing the encrypted payload, IV, and authentication tag.
     * @param ephemeralPublicKeyHex - The ephemeral public key sent by the sender in hexadecimal format.
     * @returns The decrypted payload as a string.
     */
    public static decryptPayload(
        recipientPrivateKeyHex: string,
        encryptedData: { encrypted: string, iv: string, authTag: string },
        ephemeralPublicKeyHex: string
    ): string {
        const recipientPrivateKey = ec.keyFromPrivate(recipientPrivateKeyHex.replace("0x", ""), 'hex');
        const ephemeralPublicKey = ec.keyFromPublic(ephemeralPublicKeyHex.replace("0x", ""), 'hex').getPublic();
        const sharedSecret = recipientPrivateKey.derive(ephemeralPublicKey);
        const sharedKey = crypto.createHash('sha256').update(sharedSecret.toString(16)).digest();
        const decipher = crypto.createDecipheriv('aes-256-gcm', sharedKey, Buffer.from(encryptedData.iv.replace("0x", ""), 'hex'));
        decipher.setAuthTag(Buffer.from(encryptedData.authTag.replace("0x", ""), 'hex'));

        const decrypted = Buffer.concat([
            decipher.update(Buffer.from(encryptedData.encrypted.replace("0x", ""), 'hex')),
            decipher.final()
        ]);

        return decrypted.toString('utf8');
    }
}