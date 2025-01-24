<p align="center">
  <a href="https://cmmv.io/" target="blank"><img src="https://raw.githubusercontent.com/cmmvio/docs.cmmv.io/main/public/assets/logo_CMMV2_icon.png" width="300" alt="CMMV Logo" /></a>
</p>
<p align="center">Contract-Model-Model-View (CMMV) <br/> Building scalable and modular applications using contracts.</p>
<p align="center">
    <a href="https://www.npmjs.com/package/@cmmv/encryptor"><img src="https://img.shields.io/npm/v/@cmmv/encryptor.svg" alt="NPM Version" /></a>
    <a href="https://github.com/cmmvio/cmmv-encryptor/blob/main/LICENSE"><img src="https://img.shields.io/npm/l/@cmmv/encryptor.svg" alt="Package License" /></a>
</p>

<p align="center">
  <a href="https://cmmv.io">Documentation</a> &bull;
  <a href="https://github.com/cmmvio/cmmv-encryptor/issues">Report Issue</a>
</p>

## Description

The ``@cmmv/encryptor`` module provides robust encryption and decryption functionalities for strings and objects using elliptic curve cryptography (ECC) and AES-256-GCM. It is designed specifically for CMMV applications but can also be used in Node.js environments for secure data handling. The module supports the ``secp256k1`` curve for key generation and shared secret derivation and uses AES-256-GCM for symmetric encryption, ensuring both confidentiality and integrity of the data.

## Installation

Install the ``@cmmv/encryptor`` package via npm:

```bash
$ pnpm add @cmmv/encryptor
```

## Quick Start

Below is a simple example of how to encrypt and decrypt a message using the ``Encryptor`` class:

```typescript
import { Encryptor } from "@cmmv/encryptor";

// Sample public and private keys
const recipientPublicKey = "04c19b9e3b8..."; // Replace with a real public key
const recipientPrivateKey = "3082..."; // Replace with the corresponding private key

// Encrypting a payload
const payload = "Sensitive data to be encrypted";
const encrypted = Encryptor.encryptPayload(recipientPublicKey, payload);

console.log("Encrypted payload:", encrypted);

// Decrypting the payload
const decrypted = Encryptor.decryptPayload(
    recipientPrivateKey,
    {
        encrypted: encrypted.payload,
        iv: encrypted.iv,
        authTag: encrypted.authTag
    },
    encrypted.ephemeralPublicKey
);

console.log("Decrypted payload:", decrypted);
```

### Example Classes and Methods

This class provides methods to encrypt and decrypt data using ECC and AES-256-GCM.

* ``encryptPayload(recipientPublicKeyHex: string, payload: string)``
    * Encrypts a string payload using the recipient's public key.
    * Returns an object containing:
        * ``payload``: The encrypted data in hexadecimal format.
        * ``iv``: Initialization vector for AES.
        * ``authTag``: Authentication tag for AES-GCM.
        * ``ephemeralPublicKey``: The ephemeral public key used in the encryption.
* ``decryptPayload(recipientPrivateKeyHex: string, encryptedData: { encrypted: string, iv: string, authTag: string }, ephemeralPublicKeyHex: string)``
    * Decrypts an encrypted payload using the recipient's private key and the ephemeral public key provided during encryption.
    * Returns the decrypted string payload.

## Usage Example

```typescript
import { Encryptor } from "@cmmv/encryptor";

// Encrypting data
const recipientPublicKey = "your_recipient_public_key_in_hex";
const message = "Hello, this is a secret message!";
const encryptedData = Encryptor.encryptPayload(recipientPublicKey, message);

console.log("Encrypted:", encryptedData);

// Decrypting data
const recipientPrivateKey = "your_recipient_private_key_in_hex";
const decryptedMessage = Encryptor.decryptPayload(
    recipientPrivateKey,
    {
        encrypted: encryptedData.payload,
        iv: encryptedData.iv,
        authTag: encryptedData.authTag,
    },
    encryptedData.ephemeralPublicKey
);

console.log("Decrypted:", decryptedMessage);
```

# Keys

## Generating a Mnemonic Phrase

To generate a new mnemonic phrase:
```typescript
import { Wallet } from '@cmmv/encryptor';

// Generate a 24-word mnemonic
const mnemonic = Wallet.generateMnenomic(24);
console.log('Mnemonic:', mnemonic);
```

## Deriving a Private Key

To derive the root private key from a mnemonic phrase:
```typescript
import { Wallet } from '@cmmv/encryptor';

const mnemonic = 'your mnemonic phrase here';
const privateKey = Wallet.toPrivate(mnemonic);

console.log('Private Key:', privateKey);
```

## Deriving a Public Key

To derive the public key from a mnemonic phrase using a derivation path:
```typescript
import { Wallet } from '@cmmv/encryptor';

const mnemonic = 'your mnemonic phrase here';
const derivationPath = "m/44'/0'/0'/0/0";
const publicKey = Wallet.toPublic(mnemonic, derivationPath);

console.log('Public Key:', publicKey);
```

## Custom Derivation Path

To derive a specific private key based on a custom derivation path:
```typescript
import { Wallet } from '@cmmv/encryptor';

const mnemonic = 'your mnemonic phrase here';
const derivationPath = "m/44'/60'/0'/0/0"; // Example for Ethereum
const privateKey = Wallet.toDerivatationPrivateKey(mnemonic, derivationPath);

console.log('Derived Private Key:', privateKey);
```

## Generating an Address

To generate a public address (Base58) from a private key:
```typescript
import { Wallet } from '@cmmv/encryptor';

const privateKey = 'your_private_key_hex';
const address = Wallet.privateKeyToAddress(privateKey);

console.log('Address:', address);
```

## Private Key to WIF (Wallet Import Format)

To convert a private key to Wallet Import Format (WIF):
```typescript
import { Wallet } from '@cmmv/encryptor';

const privateKey = 'your_private_key_hex';
const wifKey = Wallet.privateKeyToWIF(privateKey);

console.log('WIF Key:', wifKey);
```

## Private Key from WIF

To convert a WIF key back into a private key:
```typescript
import { Wallet } from '@cmmv/encryptor';

const wifKey = 'your_wif_key';
const { privateKey, compressed } = Wallet.wifToPrivateKey(wifKey);

console.log('Recovered Private Key:', privateKey);
console.log('Is Compressed:', compressed);
```

# Signing 

## Signing an Object

To sign an object using a private key:

```typescript
import { Signer } from '@cmmv/encryptor';

const data = { name: 'Alice', amount: 1000 };
const privateKeyHex = 'your_private_key_hex_here';
const signature = Signer.signObject(privateKeyHex, data);

console.log('Object Hash:', signature.objectHash);
console.log('Signature:', signature.signature);
```

## Verifying the Signature of an Object

To verify a signature using the public key:

```typescript
import { Signer } from '@cmmv/encryptor';

const objectHash = 'object_hash_here';
const signatureHex = 'signature_hex_here';
const publicKeyHex = 'your_public_key_hex_here';

const isValid = Signer.verifySignature(objectHash, signatureHex, publicKeyHex);
console.log('Is the signature valid?', isValid);
```

## Signing a String

To sign a string using a private key:

```typescript
import { Signer } from '@cmmv/encryptor';

const message = 'Hello, CMMV!';
const privateKeyHex = 'your_private_key_hex_here';

// Sign the string
const signedMessage = Signer.signString(privateKeyHex, message);
console.log('Signed Message:', signedMessage);
```

## Verifying a String Signature

To verify the signature of a string:

```typescript
import { Signer } from '@cmmv/encryptor';

const signedMessage = 'hash:signature';
const publicKeyHex = 'your_public_key_hex_here';

const isValid = Signer.verifyHashSignature(signedMessage, publicKeyHex);
console.log('Is the string signature valid?', isValid);
```

## Recovering a Public Key from a Signature

To recover a public key from a signature:

```typescript
import { Signer } from '@cmmv/encryptor';

const signedMessage = 'hash:signature';
const recoveryId = 1; // Typically 0 or 1

const recoveredPublicKey = Signer.recoverPublicKeyFromHash(signedMessage, recoveryId);
console.log('Recovered Public Key:', recoveredPublicKey);
```