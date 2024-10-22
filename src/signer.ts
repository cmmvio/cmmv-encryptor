import { createHash } from "node:crypto";
import * as ecc from 'tiny-secp256k1';
import BIP32Factory from "bip32";

import { Wallet } from "./wallet";

const bip32 = BIP32Factory(ecc);

export class Signer {
    /**
     * Signs a given object using a private key and returns the signature.
     * The object is first serialized using a schema, then hashed using the specified algorithm.
     * 
     * @param privateKeyHex - The private key used for signing, in hex string format.
     * @param object - The object to be signed.
     * @param schema - The JSON schema to serialize the object.
     * @param algorithm - The hashing algorithm to use (default is "sha3-256").
     * @returns An object containing the object hash and the signature in hex string format.
     * @throws Error if the signing process fails.
     */
    public static signObject(
        privateKeyHex: string, 
        object: any,
        algorithm: string = "sha3-256"
    ){
        const objectString = (typeof object === "object") ? JSON.stringify(object) : "{}";
        const hash = createHash(algorithm).update(objectString).digest('hex');
        const signature = ecc.sign(Buffer.from(hash, 'hex'), Buffer.from(privateKeyHex, 'hex'));

        const isValid = ecc.verify(
            Buffer.from(hash, 'hex'), 
            Buffer.from(Wallet.privateToPublic(privateKeyHex), "hex"), 
            signature
        );

        if (signature && isValid) {
            return {
                objectHash: hash,
                signature: Buffer.from(signature).toString('hex')
            };
        }
                    
        throw new Error('Error sign object.');
    }

    /**
     * Verifies a signature against the hash of an object and a given public key.
     * 
     * @param objectHash - The hash of the object being verified, in hex string format.
     * @param signatureHex - The signature to verify, in hex string format.
     * @param publicKeyHex - The public key used for verification, in hex string format.
     * @returns True if the signature is valid, false otherwise.
     */
    public static verifySignature(
        objectHash: any, 
        signatureHex: string,
        publicKeyHex: string | Uint8Array | undefined
    ){
        try {
            if (typeof publicKeyHex !== "string")
                publicKeyHex = Buffer.from(publicKeyHex).toString("hex");

            const isValid = ecc.verify(
                Buffer.from(objectHash.replace("0x", ""), 'hex'), 
                Buffer.from(publicKeyHex.replace("0x", ""), 'hex'),
                Buffer.from(signatureHex.replace("0x", ""), 'hex')  
            );

            return isValid;
        } catch (e) {
            return false;
        }
    }

    /**
     * Recovers the public key from a given signature and message hash.
     * The recovered public key is returned in compressed format (starting with 02 or 03).
     * 
     * @param objectHash - The hash of the object (message).
     * @param signatureHex - The signature in hex string format.
     * @param recoveryId - The recovery ID (typically 0 or 1).
     * @returns The recovered public key as a hex string in compressed format.
     * @throws Error if the public key cannot be recovered.
     */
    public static recoverPublicKey(
        objectHash: string, 
        signatureHex: string,
        recoveryId: 0 | 1 = 1 // Default is 1 for recovery ID
    ): string {
        const publicKey = ecc.recover(
            Buffer.from(objectHash.replace("0x", ""), 'hex'), 
            Buffer.from(signatureHex.replace("0x", ""), 'hex'), 
            recoveryId
        );

        if (publicKey) {
            const compressedPublicKey = ecc.pointCompress(publicKey, true);
            return Buffer.from(compressedPublicKey).toString('hex');
        }

        throw new Error('Error recovering public key.');
    }

    /**
     * Signs a given string by hashing it and returns the signature along with the hash.
     * The string is hashed using the specified algorithm and then signed.
     * 
     * @param privateKeyHex - The private key used for signing, in hex string format.
     * @param message - The string message to be signed.
     * @param algorithm - The hashing algorithm to use (default is "sha256").
     * @returns An object containing the message hash and the signature in hex string format.
     * @throws Error if the signing process fails.
     */
    public static signString(
        privateKeyHex: string, 
        message: string, 
        algorithm: string = "sha256"
    ): string {
        let hash = createHash(algorithm).update(message).digest();
    
        if (hash.length > 32) 
            hash = hash.subarray(0, 32);
        
        const key = bip32.fromPrivateKey(Buffer.from(privateKeyHex, 'hex'), Buffer.alloc(32));
        const signature = ecc.sign(hash, key.privateKey!);

        if (signature) 
            return `${hash.toString('hex')}:${Buffer.from(signature).toString('hex')}`;

        throw new Error('Error signing string.');
    }

    /**
     * Verifies a signature against a given message hash and public key.
     * 
     * @param messageHash - The hash of the message that was signed, in hex string format.
     * @param signatureHex - The signature to verify, in hex string format.
     * @param publicKeyHex - The public key used for verification, in hex string format.
     * @returns True if the signature is valid, false otherwise.
     */
    public static verifyHashSignature(
        signature: string, 
        publicKeyHex: string
    ): boolean {
        try {
            const [messageHash, signatureHex] = signature.split(":");

            const isValid = ecc.verify(
                Buffer.from(messageHash, 'hex'), 
                Buffer.from(publicKeyHex, 'hex'), 
                Buffer.from(signatureHex, 'hex')
            );

            return isValid;
        } catch {
            return false;
        }
    }

    /**
     * Recovers the public key from a given signature and message hash.
     * 
     * @param messageHash - The hash of the message that was signed, in hex string format.
     * @param signatureHex - The signature in hex string format.
     * @param recoveryId - The recovery ID (typically 0 or 1).
     * @returns The recovered public key as a hex string in compressed format.
     * @throws Error if the public key cannot be recovered.
     */
    public static recoverPublicKeyFromHash(
        signature: string,
        recoveryId: 0 | 1 = 1 // Default is 1 for recovery ID
    ): string {
        const [messageHash, signatureHex] = signature.split(":");

        const publicKey = ecc.recover(
            Buffer.from(messageHash.replace("0x", ""), 'hex'), 
            Buffer.from(signatureHex.replace("0x", ""), 'hex'), 
            recoveryId
        );

        if (publicKey) {
            const compressedPublicKey = ecc.pointCompress(publicKey, true);
            return Buffer.from(compressedPublicKey).toString('hex');
        }

        throw new Error('Error recovering public key.');
    }

    /**
     * Verifies a signature by trying both recovery IDs (0 and 1) and returns whether the message was signed by the public key.
     * 
     * @param signature - The signature in "hash:signature" format.
     * @param publicKeyHex - The public key used for verification, in hex string format.
     * @returns True if the message was signed by the public key, false otherwise.
     */
    public static signedBy(
        signature: string,
        publicKeyHex: string
    ): boolean {
        try{
            if(publicKeyHex.startsWith("0x"))
                publicKeyHex = publicKeyHex.replace("0x", "");
    
            const key0 = Signer.recoverPublicKeyFromHash(signature, 0);
            const key1 = Signer.recoverPublicKeyFromHash(signature);
            return (publicKeyHex === key0 || publicKeyHex === key1);
        }
        catch{
            return false;
        }
    }
}