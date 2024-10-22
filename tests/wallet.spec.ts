import * as bip39 from "bip39";
import { describe, expect, test, it } from 'vitest';
import { Wallet } from "../lib/wallet";

describe('wallet', () => {
	it('generate mnenomic 12 words', () => {
		const mnemonic = Wallet.generateMnenomic(12);
		expect(mnemonic.split(" ").length).toBe(12);
	});

	it('generate mnenomic 15 words', () => {
		const mnemonic = Wallet.generateMnenomic(15);
		expect(mnemonic.split(" ").length).toBe(15);
	});

	it('generate mnenomic 18 words', () => {
		const mnemonic = Wallet.generateMnenomic(18);
		expect(mnemonic.split(" ").length).toBe(18);
	});

	it('generate mnenomic 21 words', () => {
		const mnemonic = Wallet.generateMnenomic(21);
		expect(mnemonic.split(" ").length).toBe(21);
	});

	it('generate mnenomic 24 words', () => {
		const mnemonic = Wallet.generateMnenomic(24);
		expect(mnemonic.split(" ").length).toBe(24);
	});

	it('generate by entropy', () => {
		const mnemonic = Wallet.entropyToMnemonic("00000000000000000000000000000000");
		expect(mnemonic).toBe("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about");
	});

	it('generate by entropy', () => {
		const mnemonic = Wallet.entropyToMnemonic("00000000000000000000000000000fff");
		expect(mnemonic).toBe("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon advance yard");
	});

	it('generate by entropy IT', () => {
		const wordlist = bip39.wordlists.italian;
		const mnemonic = Wallet.entropyToMnemonic("00000000000000000000000000000fff", wordlist);
		expect(mnemonic).toBe("abaco abaco abaco abaco abaco abaco abaco abaco abaco abaco aforisma zibetto");
		expect(bip39.validateMnemonic(mnemonic, wordlist)).toBe(true);
	});

	it('generate by entropy CH', () => {
		const wordlist = bip39.wordlists.chinese_simplified;
		const mnemonic = Wallet.entropyToMnemonic("00000000000000000000000000000fff", wordlist);
		expect(mnemonic).toBe("的 的 的 的 的 的 的 的 的 的 分 彭");
		expect(bip39.validateMnemonic(mnemonic, wordlist)).toBe(true);
	});

	it('randomByteMnemonic', () => {
		const wordlist = bip39.wordlists.chinese_simplified;
		const mnemonic = Wallet.randomByteMnemonic(wordlist);
		expect(mnemonic.split(" ").length).toBe(24);
		expect(bip39.validateMnemonic(mnemonic, wordlist)).toBe(true);
	});

	it('randomByteMnemonic generates valid mnemonic', () => {
        const mnemonic = Wallet.randomByteMnemonic();
        expect(mnemonic.split(" ").length).toBe(24);
        expect(bip39.validateMnemonic(mnemonic)).toBe(true);
    });

	it('validate mnemonic in different languages', () => {
        const englishMnemonic = Wallet.generateMnenomic(12, bip39.wordlists.english);
        expect(bip39.validateMnemonic(englishMnemonic, bip39.wordlists.english)).toBe(true);

        const frenchMnemonic = Wallet.generateMnenomic(12, bip39.wordlists.french);
        expect(bip39.validateMnemonic(frenchMnemonic, bip39.wordlists.french)).toBe(true);

        const spanishMnemonic = Wallet.generateMnenomic(12, bip39.wordlists.spanish);
        expect(bip39.validateMnemonic(spanishMnemonic, bip39.wordlists.spanish)).toBe(true);
    });

	it('entropyToMnemonic throws error for invalid entropy', () => {
        expect(() => Wallet.entropyToMnemonic("000")).toThrow(Error);
    });

	it('entropyToMnemonic throws error for incorrect length entropy', () => {
        expect(() => Wallet.entropyToMnemonic("abcdef123456789")).toThrow(Error);
    });

	it('getSeed randomByteMnemonic', () => {
		const mnemonic = Wallet.randomByteMnemonic();
		const seed = Wallet.getSeed(mnemonic);
		expect(seed.length).toBe(128);
	});

	it('getSeed fixed entropy zero', () => {
		const mnemonic = Wallet.entropyToMnemonic("00000000000000000000000000000000");
		const seed = Wallet.getSeed(mnemonic);
		expect(mnemonic).toBe("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about");
		expect(seed).toBe("5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc19a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4");
	});

	it('getSeed fixed entropy end FFF', () => {
		const mnemonic = Wallet.entropyToMnemonic("00000000000000000000000000000fff");
		const seed = Wallet.getSeed(mnemonic);
		expect(mnemonic).toBe("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon advance yard");
		expect(seed).toBe("8a08ce2ce10285878f7079ab03d6d222c6d20c376ecb788784aab533fab82741f66cce477fec622eb12b1edccdb0436011ca71414182bd419194d106d40d5131");
		expect(bip39.validateMnemonic(mnemonic)).toBe(true);
	});

	it('getSeed fixed entropy end FFF', () => {
		const mnemonic = Wallet.entropyToMnemonic("00000000000000000000000000000fff");
		const seed = Wallet.getSeedBuffer(mnemonic);
		expect(mnemonic).toBe("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon advance yard");
		expect(Buffer.isBuffer(seed)).toBe(true);
		expect(seed.length).toBe(64);
		expect(bip39.validateMnemonic(mnemonic)).toBe(true);
	});

	it('toPrivate', () => {
		const mnemonic = Wallet.entropyToMnemonic("00000000000000000000000000000fff");
		const privateKey = Wallet.toPrivate(mnemonic);
		expect(mnemonic).toBe("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon advance yard");
		expect(bip39.validateMnemonic(mnemonic)).toBe(true);
		expect(privateKey).toBe("fe62e858a48dbdd566d7b5cc519deed0095330c0811db9114251d952a1a87f70");
	});

	it('toPrivate with passphrase', () => {
		const mnemonic = Wallet.entropyToMnemonic("00000000000000000000000000000fff");
		const privateKey = Wallet.toPrivate(mnemonic, "123456");
		expect(mnemonic).toBe("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon advance yard");
		expect(bip39.validateMnemonic(mnemonic)).toBe(true);
		expect(privateKey).toBe("bd3615b5ac1733e453c44cffb64c6273e3b2e3081603cae896da97d4fe2491fe");
	});

	it('toPrivate with passphrase test 2', () => {
		const mnemonic = Wallet.entropyToMnemonic("fff00000000000000000000000000fff");
		const privateKey = Wallet.toPrivate(mnemonic, "123456");
		expect(mnemonic).toBe("zoo length abandon abandon abandon abandon abandon abandon abandon abandon advance wrong");
		expect(bip39.validateMnemonic(mnemonic)).toBe(true);
		expect(privateKey).toBe("706107d3b4ae2c9d381d6a7386520bf9b97b4490392d9f64fda4928195b5f3c9");
	});

	it('toPrivate equal', () => {
		const mnemonic = Wallet.entropyToMnemonic("00000000000000000000000000000000");
		const privateKey = Wallet.toPrivate(mnemonic);
		const privateKey2 = Wallet.toPrivate(mnemonic);
		expect(bip39.validateMnemonic(mnemonic)).toBe(true);
		expect(privateKey).toBe(privateKey2);
		expect(privateKey).toBe("1837c1be8e2995ec11cda2b066151be2cfb48adf9e47b151d46adab3a21cdf67");
	});

	it('toPrivate diff', () => {
		const mnemonic = Wallet.entropyToMnemonic("00000000000000000000000000000000");
		const mnemonic2 = Wallet.entropyToMnemonic("0000000000000000000000000000FFFF");
		const privateKey = Wallet.toPrivate(mnemonic);
		const privateKey2 = Wallet.toPrivate(mnemonic2);
		expect(bip39.validateMnemonic(mnemonic)).toBe(true);
		expect(bip39.validateMnemonic(mnemonic2)).toBe(true);
		expect(privateKey).not.toBe(privateKey2);
		expect(privateKey).toBe("1837c1be8e2995ec11cda2b066151be2cfb48adf9e47b151d46adab3a21cdf67");
		expect(privateKey2).toBe("e0e75c3ce08f080d3c24c16c247ae16482771d6439e51b1546c0c2b3ba8dec9b");
	});

	it('toPrivate diff passphrase', () => {
		const mnemonic = Wallet.entropyToMnemonic("00000000000000000000000000000000");
		const privateKey = Wallet.toPrivate(mnemonic);
		const privateKey2 = Wallet.toPrivate(mnemonic, "123456");
		expect(bip39.validateMnemonic(mnemonic)).toBe(true);
		expect(privateKey).not.toBe(privateKey2);
		expect(privateKey).toBe("1837c1be8e2995ec11cda2b066151be2cfb48adf9e47b151d46adab3a21cdf67");
		expect(privateKey2).toBe("e3b14410e5a0b674353aed60d2678002db3f3cf2c5c4c8b9e549ab8ac745a7b3");
	});

	it('toRootKey', () => {
		const mnemonic = Wallet.entropyToMnemonic("00000000000000000000000000000000");
		const privateKey = Wallet.toPrivate(mnemonic);
		const rootKey = Wallet.toRootKey(mnemonic);
		expect(bip39.validateMnemonic(mnemonic)).toBe(true);
		expect(privateKey).toBe("1837c1be8e2995ec11cda2b066151be2cfb48adf9e47b151d46adab3a21cdf67");
		expect(rootKey).toBe("xprv9s21ZrQH143K3GJpoapnV8SFfukcVBSfeCficPSGfubmSFDxo1kuHnLisriDvSnRRuL2Qrg5ggqHKNVpxR86QEC8w35uxmGoggxtQTPvfUu");
	});

	it('toRootKey more', () => {
		const mnemonic = Wallet.entropyToMnemonic("FFF00000000000000000000000000000");
		const privateKey = Wallet.toPrivate(mnemonic);
		const rootKey = Wallet.toRootKey(mnemonic);
		expect(bip39.validateMnemonic(mnemonic)).toBe(true);
		expect(privateKey).toBe("1d57ebbe816a9baa713d9a983cde89e87a851ad302e12b410bed1ac3903a56c4");
		expect(rootKey).toBe("xprv9s21ZrQH143K2iv5yoPo9xiVmxcCBkD58KYEgr5y2fHjZrjKkQPuvxj7NZLzYHFm2xHr1YCXGGSUQPwRy2Hcteo8EjXRBsG38xoVmjtyGry");
	});

	it('toRootKey should generate different root keys with passphrase', () => {
		const mnemonic = Wallet.entropyToMnemonic("FFF00000000000000000000000000000");
		const rootKey = Wallet.toRootKey(mnemonic);
		const rootKeyWithPassphrase = Wallet.toRootKey(mnemonic, "123456");
		expect(rootKey).not.toBe(rootKeyWithPassphrase);
	});

	it('createDerivationPath should return correct path', () => {
        const path = Wallet.createDerivationPath(44, 0, 0, 0, 0);
        expect(path).toBe("m/44'/0'/0'/0/0'");

        const path2 = Wallet.createDerivationPath(49, 60, 1, 1, 5);
        expect(path2).toBe("m/49'/60'/1'/1/5'");
    });

	it('toDerivatationPrivateKey BIP 44', () => {
		const mnemonic = Wallet.entropyToMnemonic("FFF00000000000000000000000000000");
		const privateKey = Wallet.toDerivatationPrivateKey(mnemonic);
		expect(bip39.validateMnemonic(mnemonic)).toBe(true);
		expect(privateKey).toBe("e2b53129e4bebffe7cf108c1df664ca47541b4f890ec515144c767dfa0366e56");
	});

	it('toDerivatationPrivateKey BIP 49', () => {
		const mnemonic = Wallet.entropyToMnemonic("FFF00000000000000000000000000000");
		const privateKey = Wallet.toDerivatationPrivateKey(mnemonic, "m/49'/0'/0'/0/0'");
		expect(bip39.validateMnemonic(mnemonic)).toBe(true);
		expect(privateKey).toBe("2fd5c68b07858237f191185ddea3e80d3f7c4ed5431103d8b44857277d08deb2");
	});

	it('toDerivatationPrivateKey BIP 84', () => {
		const mnemonic = Wallet.entropyToMnemonic("FFF00000000000000000000000000000");
		console.log(mnemonic);
		const privateKey = Wallet.toDerivatationPrivateKey(mnemonic, "m/84'/0'/0'/0/0'");
		expect(bip39.validateMnemonic(mnemonic)).toBe(true);
		expect(privateKey).toBe("ebe4181c405f3e63363829cfe64124ae96814b055490f73bdb575719aa0fad39");
	});

	it('toDerivatationPrivateKey multi paths BIP 44', () => {
		const mnemonic = Wallet.entropyToMnemonic("FFF00000000000000000000000000000");
		const privateKey = Wallet.toDerivatationPrivateKey(mnemonic, "m/44'/0'/0'/0/0'");
		const privateKey2 = Wallet.toDerivatationPrivateKey(mnemonic, "m/44'/0'/0'/0/1'");
		const privateKey3 = Wallet.toDerivatationPrivateKey(mnemonic, "m/44'/0'/0'/0/2'");
		const privateKey4 = Wallet.toDerivatationPrivateKey(mnemonic, "m/44'/0'/0'/0/3'");
		const privateKey5 = Wallet.toDerivatationPrivateKey(mnemonic, "m/44'/0'/0'/0/4'");
		expect(bip39.validateMnemonic(mnemonic)).toBe(true);
		expect(privateKey).toBe("f45e7d57358cd42e4625e2978080dcad8cdc1ca8cfca996c962fb71367de837f");
		expect(privateKey2).toBe("e1fb2d71aee76f3a3a049452d40fbc294a18bfbe6f870f0340b155b9f97d9853");
		expect(privateKey3).toBe("f19c6ec9e56b40a3d8e6d17fd9a09b2aab7b10ce6b7b2be9ebee1f059865d344");
		expect(privateKey4).toBe("73745e7c5c833cc9bafce55f368d14621502ce45971b8701c1101e8be98cd074");
		expect(privateKey5).toBe("e57c80332bd4057ec00310e017e090a60f5e0b7d00f25ab607f0b1690f8a904d");
	});

	it('toPublic', () => {
		const mnemonic = Wallet.entropyToMnemonic("FFF00000000000000000000000000000");
		const publicKey = Wallet.toPublic(mnemonic);
		expect(bip39.validateMnemonic(mnemonic)).toBe(true);
		expect(publicKey).toBe("025986b853927acb1f483d0271ae6d61e5087830db476a66f8cd9b791e325c8cb5");
	});

	it('toPublic with passphrase', () => {
		const mnemonic = Wallet.entropyToMnemonic("FFF00000000000000000000000000000");
		const publicKey = Wallet.toPublic(mnemonic, "123456");
		expect(bip39.validateMnemonic(mnemonic)).toBe(true);
		expect(publicKey).toBe("02f08bca1c88f45742a1e8c51b18c46ed15b42e9152c04530891b61d77be251d21");
	});

	it('privateToPublic', () => {
		const mnemonic = Wallet.entropyToMnemonic("FFF00000000000000000000000000000");
		const privateKey = Wallet.toDerivatationPrivateKey(mnemonic);
		const publicKey = Wallet.privateToPublic(privateKey);
		expect(bip39.validateMnemonic(mnemonic)).toBe(true);
		expect(privateKey).toBe("e2b53129e4bebffe7cf108c1df664ca47541b4f890ec515144c767dfa0366e56");
		expect(publicKey).toBe("025986b853927acb1f483d0271ae6d61e5087830db476a66f8cd9b791e325c8cb5");
	});

	it('privateToPublic throws Error for empty private key', () => {
		expect(() => Wallet.privateToPublic("")).toThrow(Error);
	});

	it('privateKeyToWIF generates correct WIF key', () => {
        const privateKey = "1d57ebbe816a9baa713d9a983cde89e87a851ad302e12b410bed1ac3903a56c4";
        const wifKey = Wallet.privateKeyToWIF(privateKey);
        expect(wifKey.length).toBeGreaterThan(50);  
		expect(wifKey).toBe("KxCkVbTDavfXkGmH6u2iJRj8Wq4AiahSQrsh5eHdW7zDxt7zrVyo");
    });
	
	it('privateKeyToAddress generates valid address', () => {
        const privateKey = "1d57ebbe816a9baa713d9a983cde89e87a851ad302e12b410bed1ac3903a56c4";
        const address = Wallet.privateKeyToAddress(privateKey);

        expect(address.length).toBeGreaterThanOrEqual(26);
        expect(address[0]).toBe("1");
		expect(address).toBe("1N8g9yYhRyMzniKMNJeaHnbK5qYS7xSQqe");
    });

	it('privateKeyToAddress generates valid derivation address', () => {
        const mnemonic = Wallet.entropyToMnemonic("FFF00000000000000000000000000FFF");
		const privateKey = Wallet.toDerivatationPrivateKey(mnemonic, "m/84'/0'/0'/0/0'");
        const address = Wallet.privateKeyToAddress(privateKey);

        expect(address.length).toBeGreaterThanOrEqual(26);
        expect(address[0]).toBe("1");
		expect(address).toBe("121rpDuoZFi68mR6es2xL14bzTSLuc5oSb");
    });

	it('publicKeyToAddress', () => {
        const mnemonic = Wallet.entropyToMnemonic("FFF00000000000000000000000000FFF");
		const privateKey = Wallet.toDerivatationPrivateKey(mnemonic);
		const publicKey = Wallet.privateToPublic(privateKey);
		const addressFromPublic = Wallet.publicKeyToAddress(publicKey);
		expect(addressFromPublic).toBe("18pP1VA5UGSrGY9pUr5od1iYDp2F6Beays");
    });

	it('publicKeyToAddress generates valid address', () => {
        const mnemonic = Wallet.entropyToMnemonic("FFF00000000000000000000000000FFF");
		const privateKey = Wallet.toDerivatationPrivateKey(mnemonic);
		const publicKey = Wallet.privateToPublic(privateKey);
        const addressFromPrivate = Wallet.privateKeyToAddress(privateKey);
		const addressFromPublic = Wallet.publicKeyToAddress(publicKey);
		expect(addressFromPrivate).toBe(addressFromPublic);
    });

	it('wifToPrivateKey privateKeyToWIF', () => {
        const mnemonic = Wallet.entropyToMnemonic("FFF00000000000000000000000000000");
		const privateKey = Wallet.toDerivatationPrivateKey(mnemonic);
		const wif = Wallet.privateKeyToWIF(privateKey);
		const wifToPrivate = Wallet.wifToPrivateKey(wif);
		expect(wif).toBe("L4pQDqNQLb7j7Wgj9fJRZk8SBPoEvXV2t3uqKQNWaYixonKbTpgu");
		expect(wifToPrivate.privateKey).toBe(privateKey);
    });

	it('wifToPrivateKey should return correct private key and compression status', () => {
        const wif = "L1DKMaeJsKUWA2MC8Ki557CaPDXvAHuZJvueiDarRupKPFBRmh3P"; // Example WIF key
        const { privateKey, compressed } = Wallet.wifToPrivateKey(wif);
        
        expect(privateKey).toBe("7725a883e38d36136c308d1740556f9b2f9f576d02d125b98963665c71ab0f28"); // Replace with the actual private key in hex
        expect(compressed).toBe(true); // Check if it correctly identifies compressed key
    });

	it('wifToPrivateKey should throw an error for invalid WIF', () => {
        const invalidWif = "invalidWIFkeyExample";
        expect(() => Wallet.wifToPrivateKey(invalidWif)).toThrowError('Non-base58 character');
    });

	it('privateKeyToWIF should return a valid WIF format', () => {
		const mnemonic = Wallet.entropyToMnemonic("FFF00000000000000000000000000FFF");
		const privateKey = Wallet.toDerivatationPrivateKey(mnemonic);
       	const wif = Wallet.privateKeyToWIF(privateKey);

        const { privateKey: derivedPrivateKey, compressed } = Wallet.wifToPrivateKey(wif);

        expect(derivedPrivateKey).toBe(privateKey); 
        expect(compressed).toBe(true);
    });

	it('privateKeyToWIF should generate WIF for uncompressed public key', () => {
        const mnemonic = Wallet.entropyToMnemonic("FFF00000000000000000000000000FFF");
		const privateKey = Wallet.toDerivatationPrivateKey(mnemonic);
		const wif = Wallet.privateKeyToWIF(privateKey, false); 

        const { privateKey: derivedPrivateKey, compressed } = Wallet.wifToPrivateKey(wif);

        expect(derivedPrivateKey).toBe(privateKey); // The derived private key should match the original
        expect(compressed).toBe(false); // Should correctly identify that the key is uncompressed
    });


	it('full generation', () => {
        const mnemonic = Wallet.entropyToMnemonic("FFF000000000000000FFF00000000FFF");
		const seed = Wallet.getSeed(mnemonic);
		const privateKey = Wallet.toDerivatationPrivateKey(mnemonic);
		const publicKey = Wallet.toPublic(mnemonic);
		const privateWiF = Wallet.privateKeyToWIF(privateKey);
		const wifToPrivate = Wallet.wifToPrivateKey(privateWiF);
		const address = Wallet.publicKeyToAddress(publicKey);
		        
		expect(mnemonic).toBe("zoo length abandon abandon abandon abandon advance wrap abandon abandon advance young"); 
        expect(seed).toBe("c1c64f4113b309b0403dcfd4c3209bd6c590ece7d90bab5f1e8e000a384ac2c810fb0159670a7039bec50b28b30cddc2e8b19b89c294b6bdad73e2b0eaa3c3bc"); 
		expect(privateKey).toBe("cc5afac4440ca38546fb43ae3371df328030bc5780d9fc70236eb37c47f63cb4"); 
		expect(publicKey).toBe("02d0e0940eaa570f87027a7d366557d9d7b44780c0eaccd7b62e7bde04f1e82755"); 
		expect(address).toBe("1JMTppg33bxhEkLMxzQLsGjG8RL3xGubY8"); 
		expect(privateWiF).toBe("L44x7bZodCRsapm6k8UFAFKxDd4r1RJ6HAeSumzn1XweNv88ai9X"); 
		expect(wifToPrivate.privateKey).toBe(privateKey); 
    });
});
