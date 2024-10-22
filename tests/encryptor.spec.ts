import { describe, expect, it } from 'vitest';
import { Encryptor } from "../src/encryptor";
import { ec as EC } from 'elliptic';

const ec = new EC('secp256k1');

describe('Encryptor', () => {
    const recipientKeyPair = ec.genKeyPair();
    const recipientPrivateKey = recipientKeyPair.getPrivate('hex');
    const recipientPublicKey = recipientKeyPair.getPublic('hex');

    const otherKeyPair = ec.genKeyPair();
    const otherPrivateKey = otherKeyPair.getPrivate('hex');
    const otherPublicKey = otherKeyPair.getPublic('hex');

    it('should encrypt and decrypt a simple string correctly', () => {
        const payload = "Hello, Blockchain!";
        const encryptedData = Encryptor.encryptPayload(recipientPublicKey, payload);
        const decryptedPayload = Encryptor.decryptPayload(recipientPrivateKey, {
            encrypted: encryptedData.payload,
            iv: encryptedData.iv,
            authTag: encryptedData.authTag
        }, encryptedData.ephemeralPublicKey);
        expect(decryptedPayload).toBe(payload);
    });

    it('should handle encryption and decryption of an empty string', () => {
        const payload = "";
        const encryptedData = Encryptor.encryptPayload(recipientPublicKey, payload);
        const decryptedPayload = Encryptor.decryptPayload(recipientPrivateKey, {
            encrypted: encryptedData.payload,
            iv: encryptedData.iv,
            authTag: encryptedData.authTag
        }, encryptedData.ephemeralPublicKey);
        expect(decryptedPayload).toBe(payload);
    });

    it('should handle encryption and decryption of a string with special characters', () => {
        const payload = "Hello! @#%*&^$()_+-=[]{}|;:',.<>/?`~";
        const encryptedData = Encryptor.encryptPayload(recipientPublicKey, payload);
        const decryptedPayload = Encryptor.decryptPayload(recipientPrivateKey, {
            encrypted: encryptedData.payload,
            iv: encryptedData.iv,
            authTag: encryptedData.authTag
        }, encryptedData.ephemeralPublicKey);
        expect(decryptedPayload).toBe(payload);
    });

    it('should fail to decrypt with an incorrect private key', () => {
        const payload = "Sensitive Data";
        const encryptedData = Encryptor.encryptPayload(recipientPublicKey, payload);
    
        expect(() => {
            Encryptor.decryptPayload(otherPrivateKey, {
                encrypted: encryptedData.payload,
                iv: encryptedData.iv,
                authTag: encryptedData.authTag
            }, encryptedData.ephemeralPublicKey);
        }).toThrow("Unsupported state or unable to authenticate data");
    });

    it('should throw an error when decrypting with tampered encrypted data', () => {
        const payload = "Tamper Test";
        const encryptedData = Encryptor.encryptPayload(recipientPublicKey, payload);
        
        const tamperedData = {
            encrypted: encryptedData.payload.slice(0, -2) + '00',
            iv: encryptedData.iv,
            authTag: encryptedData.authTag
        };

        expect(() => {
            Encryptor.decryptPayload(recipientPrivateKey, tamperedData, encryptedData.ephemeralPublicKey);
        }).toThrow();
    });

    it('should produce different encrypted outputs for the same payload due to randomness', () => {
        const payload = "Consistent Message";
        const encryptedData1 = Encryptor.encryptPayload(recipientPublicKey, payload);
        const encryptedData2 = Encryptor.encryptPayload(recipientPublicKey, payload);
        expect(encryptedData1.payload).not.toBe(encryptedData2.payload);
        expect(encryptedData1.iv).not.toBe(encryptedData2.iv);
        expect(encryptedData1.authTag).not.toBe(encryptedData2.authTag);
        expect(encryptedData1.ephemeralPublicKey).not.toBe(encryptedData2.ephemeralPublicKey);
    });

    it('should throw an error when encrypting with an invalid public key', () => {
        const invalidPublicKey = 'invalidpublickey';
        const payload = "Invalid Key Test";

        expect(() => {
            Encryptor.encryptPayload(invalidPublicKey, payload);
        }).toThrow();
    });

    it('should throw an error when decrypting with missing fields', () => {
        const payload = "Missing Fields Test";
        const encryptedData = Encryptor.encryptPayload(recipientPublicKey, payload);
        
        const incompleteData = {
            encrypted: encryptedData.payload,
            iv: encryptedData.iv
        };

        expect(() => {
            Encryptor.decryptPayload(recipientPrivateKey, incompleteData as any, encryptedData.ephemeralPublicKey);
        }).toThrow();
    });

    it('should handle encryption and decryption of a large payload', () => {
        const payload = "A".repeat(10000); 
        const encryptedData = Encryptor.encryptPayload(recipientPublicKey, payload);
        const decryptedPayload = Encryptor.decryptPayload(recipientPrivateKey, {
            encrypted: encryptedData.payload,
            iv: encryptedData.iv,
            authTag: encryptedData.authTag
        }, encryptedData.ephemeralPublicKey);
        expect(decryptedPayload).toBe(payload);
    });

    it('should throw an error when decrypting with an invalid ephemeral public key', () => {
        const payload = "Invalid Ephemeral Key Test";
        const encryptedData = Encryptor.encryptPayload(recipientPublicKey, payload);
        
        const invalidEphemeralPublicKey = 'invalidephemeralkey';

        expect(() => {
            Encryptor.decryptPayload(recipientPrivateKey, {
                encrypted: encryptedData.payload,
                iv: encryptedData.iv,
                authTag: encryptedData.authTag
            }, invalidEphemeralPublicKey);
        }).toThrow();
    });
});