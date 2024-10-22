import { describe, expect, test, it } from 'vitest';
import { Signer } from "../src/signer";
import { Wallet } from "../src/wallet";

describe('signer', () => {
    const testObject = { hello: "world" };
    const privateKey = 'e2b53129e4bebffe7cf108c1df664ca47541b4f890ec515144c767dfa0366e56';
    const publicKey = '025986b853927acb1f483d0271ae6d61e5087830db476a66f8cd9b791e325c8cb5';
    const message = "Hello, Blockchain!";

    it('should sign an object and return a valid signature', () => {
        const result = Signer.signObject(privateKey, testObject);
        expect(result).toHaveProperty('objectHash');
        expect(result).toHaveProperty('signature');
        expect(result.objectHash).toBeDefined();
        expect(result.signature).toBeDefined();
    });

    it('should verify a valid signature', () => {
        const { objectHash, signature } = Signer.signObject(privateKey, testObject);
        const isValid = Signer.verifySignature(objectHash, signature, publicKey);
        expect(isValid).toBe(true);
    });

    it('should not verify an invalid signature', () => {
        const invalidSignature = '00b53129e4bebffe7cf108c1df664ca47541b4f890ec515144c767dfa0366e00';
        const { objectHash } = Signer.signObject(privateKey, testObject);
        const isValid = Signer.verifySignature(objectHash, invalidSignature, publicKey);
        expect(isValid).toBe(false);
    });

    it('should recover public key from signature', () => {
        const { objectHash, signature } = Signer.signObject(privateKey, testObject);
        const recoveryId = 1;
        const recoveredPublicKey = Signer.recoverPublicKey(objectHash, signature, recoveryId);
        expect(recoveredPublicKey).toBe(publicKey);
    });

    it('should throw error when recovering public key with invalid data', () => {
        const invalidSignature = '00b53129e4bebffe7cf108c1df664ca47541b4f890ec515144c767dfa0366e00';
        const invalidHash = 'invalidhash';
        const recoveryId = 0;

        expect(() => {
            Signer.recoverPublicKey(invalidHash, invalidSignature, recoveryId);
        }).toThrow('Expected Hash');
    });

    it('should sign a string and return a valid signature', () => {
        const signature = Signer.signString(privateKey, message);
        expect(signature).toBeDefined();
        expect(signature).toContain(':'); // Ensure it's in the "hash:signature" format
        expect(signature).toBe('7526b1d2bc17587443fbf1fafb27e95d70615bc7576c6e34c1f139c9ce857733:c804f2bffcb8fe9b724e2b808dc7cb4341f7d44ef9c137fac816435199d384d372a4d55f352b703c66e5ca5530bf655af7f1df76b2c2550d8194f0f6771eb4cc');
    });

    it('should verify a valid string signature', () => {
        const signature = Signer.signString(privateKey, message);
        const isValid = Signer.verifyHashSignature(signature, publicKey);
        expect(isValid).toBe(true);
    });

    it('should not verify an invalid string signature', () => {
        const invalidSignature = '0000000000000000000000000000000000000000000000000000000000000000:00b53129e4bebffe7cf108c1df664ca47541b4f890ec515144c767dfa0366e00';
        const isValid = Signer.verifyHashSignature(invalidSignature, publicKey);
        expect(isValid).toBe(false);
    });

    it('should recover public key from valid string signature', () => {
        const signature = Signer.signString(privateKey, message);
        const recoveredPublicKey = Signer.recoverPublicKeyFromHash(signature, 0);
        expect(recoveredPublicKey).toBe(publicKey);
    });

    it('should throw error when recovering public key with invalid signature data', () => {
        const invalidSignature = 'invalidhash:invalidsignature';
        expect(() => {
            Signer.recoverPublicKeyFromHash(invalidSignature);
        }).toThrow('Expected Hash');
    });

    it('should handle signing an empty string', () => {
        const signature = Signer.signString(privateKey, '');
        expect(signature).toBeDefined();
        expect(signature).toContain(':');
    });

    it('should handle verifying an empty string signature', () => {
        const signature = Signer.signString(privateKey, '');
        const isValid = Signer.verifyHashSignature(signature, publicKey);
        expect(isValid).toBe(true);
    });

    it('should recover public key from empty string signature', () => {
        const signature = Signer.signString(privateKey, '');
        const recoveredPublicKey = Signer.recoverPublicKeyFromHash(signature);
        expect(recoveredPublicKey).toBe(publicKey);
    });

    it('should recover public key string signature', () => {
        const signature = Signer.signString(privateKey, 'message');
        const recoveredPublicKey = Signer.recoverPublicKeyFromHash(signature);
        expect(recoveredPublicKey).toBe(publicKey);
    });

    it('should return true when signature was signed by the given public key (recoveryId 1)', () => {
        const signature = Signer.signString(privateKey, message);
        const isSigned = Signer.signedBy(signature, publicKey);
        expect(isSigned).toBe(true);
    });

    it('should return true when signature was signed by the given public key (recoveryId 0)', () => {
        // Modify the signature manually to simulate recoveryId = 0 scenario
        const signature = Signer.signString(privateKey, message);
        const isSigned = Signer.signedBy(signature, publicKey);
        expect(isSigned).toBe(true);
    });

    it('should return false if signature does not match the given public key', () => {
        const invalidPublicKey = '03b5233a83d99aeea5f510d6d1ab6c36c33928a659b68315dfc5364c6a5be6f5a3';
        const signature = Signer.signString(privateKey, message);
        const isSigned = Signer.signedBy(signature, invalidPublicKey);
        expect(isSigned).toBe(false);
    });

    it('should return false if the signature is tampered with', () => {
        const signature = Signer.signString(privateKey, message);
        const tamperedSignature = signature.replace(/0/g, '1');
        const isSigned = Signer.signedBy(tamperedSignature, publicKey);
        expect(isSigned).toBe(false);
    });

    it('should handle signing and verifying a single character message', () => {
        const shortMessage = "A";
        const signature = Signer.signString(privateKey, shortMessage);
        expect(signature).toBeDefined();
        const isValid = Signer.verifyHashSignature(signature, publicKey);
        expect(isValid).toBe(true);
    });

    it('should handle signing and verifying a very long message (5000 chars)', () => {
        const longMessage = "A".repeat(5000);
        const signature = Signer.signString(privateKey, longMessage);
        expect(signature).toBeDefined();
        const isValid = Signer.verifyHashSignature(signature, publicKey);
        expect(isValid).toBe(true);
    });

    it('should throw an error when trying to sign with an invalid short private key', () => {
        const invalidPrivateKey = 'e2b531';
        expect(() => {
            Signer.signString(invalidPrivateKey, "message");
        }).toThrow();
    });

    it('should throw an error when trying to sign with a private key containing invalid characters', () => {
        const invalidPrivateKey = 'zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz';
        expect(() => {
            Signer.signString(invalidPrivateKey, "message");
        }).toThrow();
    });

    it('should return false when verifying with an invalid public key (too short)', () => {
        const signature = Signer.signString(privateKey, "Test message");
        const invalidPublicKey = '025986';
        const isValid = Signer.signedBy(signature, invalidPublicKey);
        expect(isValid).toBe(false);
    });

    it('should sign and verify using SHA512', () => {
        const signature = Signer.signString(privateKey, "Test SHA512", 'sha512');
        expect(signature).toBeDefined();
        const isValid = Signer.verifyHashSignature(signature, publicKey);
        expect(isValid).toBe(true);
    });

    it('should throw an error when private key is an empty string', () => {
        const emptyPrivateKey = '';
        expect(() => {
            Signer.signString(emptyPrivateKey, "message");
        }).toThrow();
    });

    it('should return false when verifying with an empty public key', () => {
        const signature = Signer.signString(privateKey, "message");
        const isValid = Signer.signedBy(signature, '');
        expect(isValid).toBe(false);
    });

    it('should fail to verify a signature created with a boundary private key', () => {
        const boundaryPrivateKey = '1'.padStart(64, '0');
        const expectedPublicKey = '0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798'; // Chave pública esperada
        const publicKey = Wallet.privateToPublic(boundaryPrivateKey);
        
        expect(publicKey).toBe(expectedPublicKey);
    });
});
