import * as crypto from 'node:crypto';
import * as bip39 from 'bip39';
import * as ecc from 'tiny-secp256k1';
import bs58 from 'bs58';
import { ec as EC } from 'elliptic';
import BIP32Factory from 'bip32';

// Initialize BIP32 using tiny-secp256k1
const ec = new EC('secp256k1');
const bip32 = BIP32Factory(ecc);

// Network interface for custom networks like Bitcoin, Ethereum, etc.
interface Network {
    wif: number;
    bip32: {
        public: number;
        private: number;
    };
    messagePrefix?: string;
    bech32?: string;
    pubKeyHash?: number;
    scriptHash?: number;
}

export class Wallet {
    /**
     * Returns the entropy size in bits for the given word count of a mnemonic phrase.
     *
     * @param size - The number of words (must be 12, 15, 18, 21, or 24).
     * @returns The entropy size in bits.
     * @throws Error if the word count is invalid.
     */
    public static getEntropyForWordCount(size: number): number {
        const wordToEntropyMap: { [key: number]: number } = {
            3: 32,
            6: 64,
            9: 96,
            12: 128,
            15: 160,
            18: 192,
            21: 224,
            24: 256,
        };

        if (!wordToEntropyMap[size])
            throw new Error(`Invalid length. Use 12, 15, 18, 21 or 24 words.`);

        return wordToEntropyMap[size];
    }

    /**
     * Generates a mnemonic phrase using the specified word count and wordlist.
     *
     * @param size - The number of words (default is 24).
     * @param wordlists - The wordlist to use (default is English).
     * @returns A mnemonic phrase.
     */
    public static generateMnenomic(
        size: number = 24,
        wordlists: string[] = bip39.wordlists.english,
    ): string {
        const entropy = Wallet.getEntropyForWordCount(size);
        return bip39.generateMnemonic(entropy, undefined, wordlists);
    }

    /**
     * Converts entropy to a mnemonic phrase using a specified wordlist.
     *
     * @param entropy - The entropy to convert (as Buffer or hex string).
     * @param wordlists - The wordlist to use (default is English).
     * @returns A mnemonic phrase.
     */
    public static entropyToMnemonic(
        entropy: Buffer | string,
        wordlists: string[] = bip39.wordlists.english,
    ) {
        return bip39.entropyToMnemonic(entropy, wordlists);
    }

    /**
     * Generates a random mnemonic phrase using 32 bytes of random entropy.
     *
     * @param wordlists - The wordlist to use (default is English).
     * @returns A mnemonic phrase.
     */
    public static randomByteMnemonic(
        wordlists: string[] = bip39.wordlists.english,
    ) {
        const entropy = crypto.randomBytes(32).toString('hex');
        return bip39.entropyToMnemonic(entropy, wordlists);
    }

    /**
     * Converts a mnemonic phrase to a seed in hexadecimal format.
     *
     * @param mnemonic - The mnemonic phrase.
     * @returns The seed as a hex string.
     */
    public static getSeed(mnemonic: string) {
        return bip39.mnemonicToSeedSync(mnemonic).toString('hex');
    }

    /**
     * Converts a mnemonic phrase to a seed as a Buffer.
     *
     * @param mnemonic - The mnemonic phrase.
     * @returns The seed as a Buffer.
     */
    public static getSeedBuffer(mnemonic: string) {
        return bip39.mnemonicToSeedSync(mnemonic);
    }

    /**
     * Derives the root private key from a mnemonic phrase and optional passphrase.
     *
     * @param mnemonic - The mnemonic phrase.
     * @param passphrase - The passphrase to use (default is empty string).
     * @returns The root private key as a hex string.
     * @throws Error if the private key cannot be derived.
     */
    public static toPrivate(mnemonic: string, passphrase: string = '') {
        const seed = bip39.mnemonicToSeedSync(mnemonic, passphrase);
        const rootKey = bip32.fromSeed(seed);

        if (rootKey.privateKey)
            return Buffer.from(rootKey.privateKey).toString('hex');

        throw new Error('Error deriving private key.');
    }

    /**
     * Creates a BIP derivation path based on the given parameters.
     *
     * @param bip - The BIP number (default is 44).
     * @param coinType - The coin type (0 for Bitcoin, 60 for Ethereum, etc.).
     * @param account - The account number (default is 0).
     * @param change - Whether the address is for receiving (0) or change (1).
     * @param addressIndex - The index of the address (default is 0).
     * @returns A derivation path as a string.
     */
    public static createDerivationPath(
        bip: number = 44,
        coinType: number = 0, // Coin Type (0 para Bitcoin, 60 para Ethereum, etc.)
        account: number = 0, // Número da conta (0 por padrão)
        change: number = 0, // 0 para recebimento, 1 para troco
        addressIndex: number = 0, // Índice do endereço
    ): string {
        return `m/${bip}'/${coinType}'/${account}'/${change}/${addressIndex}'`;
    }

    /**
     * Derives the private key from a mnemonic phrase using a specific derivation path.
     *
     * @param mnemonic - The mnemonic phrase.
     * @param derivationPath - The derivation path (default is "m/44'/0'/0'/0/0").
     * @param passphrase - The passphrase to use (default is empty string).
     * @returns The derived private key as a hex string.
     * @throws Error if the private key cannot be derived.
     */
    public static toDerivatationPrivateKey(
        mnemonic: string,
        derivationPath: string = "m/44'/0'/0'/0/0",
        passphrase: string = '',
    ) {
        const seed = bip39.mnemonicToSeedSync(mnemonic, passphrase);
        const rootKey = bip32.fromSeed(seed);
        const child = rootKey.derivePath(derivationPath);

        if (child.privateKey)
            return Buffer.from(child.privateKey).toString('hex');

        throw new Error('Error deriving private key.');
    }

    /**
     * Derives the root key in Base58 format from a mnemonic phrase and optional network.
     *
     * @param mnemonic - The mnemonic phrase.
     * @param passphrase - The passphrase to protect the mnemonic (optional).
     * @param network - The network parameters (optional).
     * @returns The root key in Base58 format.
     */
    public static toRootKey(
        mnemonic: string,
        passphrase: string = '',
        network?: Network,
    ) {
        const seed = bip39.mnemonicToSeedSync(mnemonic, passphrase);
        const rootKey = bip32.fromSeed(seed, network);
        return rootKey.toBase58();
    }

    /**
     * Derives the public key from a mnemonic phrase using a specific derivation path.
     *
     * @param mnemonic - The mnemonic phrase.
     * @param derivationPath - The derivation path (default is "m/44'/0'/0'/0/0").
     * @param passphrase - The passphrase to use (default is empty string).
     * @returns The derived public key as a hex string.
     * @throws Error if the public key cannot be derived.
     */
    public static toPublic(
        mnemonic: string,
        derivationPath: string = "m/44'/0'/0'/0/0",
        passphrase: string = '',
    ): string {
        const seed = bip39.mnemonicToSeedSync(mnemonic, passphrase);
        const rootKey = bip32.fromSeed(seed);
        const child = rootKey.derivePath(derivationPath);

        if (child.publicKey)
            return Buffer.from(child.publicKey).toString('hex');

        throw new Error('Error deriving public key.');
    }

    /**
     * Derives the public key from a given private key.
     *
     * @param privateKey - The private key in hex string format.
     * @returns The derived public key as a hex string.
     * @throws Error if the public key cannot be derived.
     */
    public static privateToPublic(privateKey: string | Uint8Array): string {
        if (typeof privateKey !== 'string')
            privateKey = Buffer.from(privateKey).toString('hex');

        const keyPair = bip32.fromPrivateKey(
            Buffer.from(privateKey, 'hex'),
            Buffer.alloc(32),
        );

        if (keyPair.publicKey)
            return Buffer.from(keyPair.publicKey).toString('hex');

        throw new Error('Error deriving public key from private key.');
    }

    /**
     * Derives the public key directly from a derived BIP32 key (from mnemonic or path).
     *
     * @param bip32Key - The derived BIP32 key object from which to get the public key.
     * @returns The public key in hex format.
     */
    public static bip32ToPublic(bip32Key: any): string {
        if (bip32Key.publicKey)
            return Buffer.from(bip32Key.publicKey).toString('hex');

        throw new Error('Error deriving public key from BIP32 key.');
    }

    /**
     * Converts a private key into WIF (Wallet Import Format).
     *
     * @param privateKey - The private key in hexadecimal format.
     * @param compressed - Whether the public key will be compressed (default is true).
     * @returns The private key in WIF format (Base58).
     */
    public static privateKeyToWIF(
        privateKey: string,
        compressed: boolean = true,
    ): string {
        const prefix = Buffer.from([0x80]);
        const privateKeyBuffer = Buffer.from(privateKey, 'hex');
        const suffix = compressed ? Buffer.from([0x01]) : Buffer.alloc(0);
        const extendedKey = Buffer.concat([prefix, privateKeyBuffer, suffix]);
        const checksum = crypto
            .createHash('sha256')
            .update(crypto.createHash('sha256').update(extendedKey).digest())
            .digest()
            .subarray(0, 4);
        const finalKey = Buffer.concat([extendedKey, checksum]);
        return bs58.encode(finalKey);
    }

    /**
     * Converts a WIF (Wallet Import Format) key back into a private key.
     *
     * @param wif - The WIF encoded private key.
     * @returns The private key in hexadecimal format.
     * @throws Error if the WIF key is invalid.
     */
    public static wifToPrivateKey(wif: string): {
        privateKey: string;
        compressed: boolean;
    } {
        const decoded = bs58.decode(wif);
        const privateKey = decoded.slice(1, 33); // 32 bytes of private key
        const suffix = decoded.slice(33, 34); // Optional suffix for compressed keys

        const checksum = decoded.slice(decoded.length - 4);
        const keyWithoutChecksum = decoded.slice(0, decoded.length - 4);

        const newChecksum = crypto
            .createHash('sha256')
            .update(
                crypto.createHash('sha256').update(keyWithoutChecksum).digest(),
            )
            .digest()
            .subarray(0, 4);

        if (!Buffer.from(checksum).equals(newChecksum))
            throw new Error('Invalid WIF checksum');

        const compressed = Buffer.from(suffix).equals(Buffer.from([0x01]));

        return {
            privateKey: Buffer.from(privateKey).toString('hex'),
            compressed,
        };
    }

    /**
     * Generates a public address (Base58) from a private key.
     *
     * @param privateKey - The private key in hexadecimal format.
     * @returns The public address in Base58 format.
     */
    public static privateKeyToAddress(
        privateKey: string | Uint8Array | undefined,
    ): string {
        if (typeof privateKey !== 'string')
            privateKey = Buffer.from(privateKey).toString('hex');

        const keyPair = ec.keyFromPrivate(privateKey);
        const publicKey = keyPair.getPublic(true, 'hex'); // Compressed form
        const sha256Hash = crypto
            .createHash('sha256')
            .update(Buffer.from(publicKey, 'hex'))
            .digest();
        const ripemd160Hash = crypto
            .createHash('ripemd160')
            .update(sha256Hash)
            .digest();

        const prefix = Buffer.from([0x00]);
        const extendedPublicKey = Buffer.concat([prefix, ripemd160Hash]);

        const checksum = crypto
            .createHash('sha256')
            .update(
                crypto.createHash('sha256').update(extendedPublicKey).digest(),
            )
            .digest()
            .slice(0, 4);
        const finalPublicKey = Buffer.concat([extendedPublicKey, checksum]);

        return bs58.encode(finalPublicKey);
    }

    /**
     * Generates a public address (Base58) from a public key.
     *
     * @param publicKey - The public key in hexadecimal format.
     * @returns The public address in Base58 format.
     */
    public static publicKeyToAddress(publicKey: string): string {
        const sha256Hash = crypto
            .createHash('sha256')
            .update(Buffer.from(publicKey, 'hex'))
            .digest();
        const ripemd160Hash = crypto
            .createHash('ripemd160')
            .update(sha256Hash)
            .digest();

        const prefix = Buffer.from([0x00]);
        const extendedPublicKey = Buffer.concat([prefix, ripemd160Hash]);
        const checksum = crypto
            .createHash('sha256')
            .update(
                crypto.createHash('sha256').update(extendedPublicKey).digest(),
            )
            .digest()
            .slice(0, 4);
        const finalPublicKey = Buffer.concat([extendedPublicKey, checksum]);

        return bs58.encode(finalPublicKey);
    }
}
