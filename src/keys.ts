import { ec as EC } from 'elliptic';

export class ECKeys {
    /**
     * Generates a new elliptic curve key pair.
     *
     * @returns {EC.KeyPair} - A key pair object containing both private and public keys.
     */
    public static generateKeys(): EC.KeyPair {
        const ec = new EC('secp256k1');
        const recipientKeyPair = ec.genKeyPair();
        return recipientKeyPair;
    }

    /**
     * Extracts the private key from a given elliptic curve key pair.
     *
     * @param {EC.KeyPair} keyPair - The key pair object from which to extract the private key.
     * @returns {string} - The private key in hexadecimal format.
     */
    public static getPrivateKey(keyPair: EC.KeyPair): string {
        return keyPair.getPrivate('hex');
    }

    /**
     * Extracts the public key from a given elliptic curve key pair.
     *
     * @param {EC.KeyPair} keyPair - The key pair object from which to extract the public key.
     * @returns {string} - The public key in hexadecimal format.
     */
    public static getPublicKey(keyPair: EC.KeyPair): string {
        return keyPair.getPublic('hex');
    }
}
