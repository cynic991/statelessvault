/**** Stateless Vault by Andrea Guerini is licensed under the Creative Commons Attribution 4.0 International License. 
To view a copy of this license, visit http://creativecommons.org/licenses/by/4.0/. 
Based on works by Maarten Billemont (https://github.com/Lyndir/MasterPassword/) 
and by Tom Thorogood (https://github.com/tmthrgd/mpw-js).  ****/

/*
Package pbkdf2 implements the key derivation function PBKDF2 as defined in RFC
2898 / PKCS #5 v2.0.
A key derivation function is useful when encrypting data based on a password
or any other not-fully-random data. It uses a pseudorandom function to derive
a secure encryption key based on the password.
While v2.0 of the standard defines only one pseudorandom function to use,
HMAC-SHA1, the drafted v2.1 specification allows use of all five FIPS Approved
Hash Functions SHA-1, SHA-224, SHA-256, SHA-384 and SHA-512 for HMAC. To
choose, you can pass the `New` functions from the different SHA packages to
pbkdf2.Key.
Here SHA-1 is discarded. If you want, you can add it and algorithm will work.
*/

// https://bugzilla.mozilla.org/show_bug.cgi?id=554827
window.pbkdf2 = function () {
	// https://github.com/golang/crypto/blob/master/pbkdf2/pbkdf2.go
	function pbkdf2_js(password, salt, iter, keyLen, hash) {
		switch ((hash.name || hash).toUpperCase()) {
			case "SHA224":				/* This version supports only SHA-2 algorithms, SHA-1 has been discarded*/
			case "SHA-224":
				var hashLen = 224 / 8;
				break;
			case "SHA256":
			case "SHA-256":
				var hashLen = 256 / 8;
				break;
			case "SHA384":
			case "SHA-384":
				var hashLen = 384 / 8;
				break;
			case "SHA512":
			case "SHA-512":
				var hashLen = 512 / 8;
				break;
			default:
				let err = new Error("A parameter or an operation is not supported by the underlying object");
				err.name = "InvalidAccessError";
				return Promise.reject(err);
		}
		
		let numBlocks = ((keyLen + hashLen - 1) / hashLen) | 0;
		
		let data     = new Uint8Array(salt.length + 4/*sizeof(uint32)*/);
		let dataView = new DataView(data.buffer, data.byteOffset, data.byteLength);
		
		data.set(salt);
		
		return window.crypto.subtle.importKey("raw", password, {
				name: "HMAC",
				hash: hash
			}, false/*not extractable*/, [ "sign" ]).then(function (key) {
				let dk = new Uint8Array(numBlocks * hashLen);
				let x = Promise.resolve();
				
				for (let block = 1, dki = 0; block <= numBlocks; block++, dki += hashLen) {
					x = x.then(() => dataView.setUint32(salt.length, block, false/*big-endian*/))
						.then(() => window.crypto.subtle.sign({
							name: "HMAC",
							hash: hash
						}, key, data))
						.then(pdk => (dk.set(new Uint8Array(pdk), dki), pdk));
					
					for (let n = 2; n <= iter; n++) {
						x = x.then(U => window.crypto.subtle.sign({
								name: "HMAC",
								hash: hash
							}, key, U)).then(function (U) {
								let Ux = new Uint8Array(U);
								
								for (let i = 0; i < Ux.length; i++) {
									dk[dki + i] ^= Ux[i];
								}
								
								return U;
							});
					}
				}
				
				return x.then(() => dk.subarray(0, keyLen));
			});
	}
	

	return function (password, salt, iter, keyLen, hash) {
		let self = this;
		let args = arguments;
			
		return window.crypto.subtle.importKey("raw", password, {
				name: "PBKDF2",
				hash: hash
			}, false/*not extractable*/, [ "deriveBits" ])
			.then(key => window.crypto.subtle.deriveBits({
				name: "PBKDF2",
				salt: salt,
				iterations: iter,
				hash: hash
			}, key, keyLen * 8))
			.then(key => new Uint8Array(key))
			.catch(err =>
				// PBKDF2-HMAC is not supported by the Web Crytpto API if either a
				// NotSupportedError or a OperationError are emmited
				(err.name === "OperationError" || err.name === "NotSupportedError")
					? (window.pbkdf2 = pbkdf2_js).apply(self, args)
					// Limited support for PBKDF2-HMAC-SHA exists if InvalidAccessError
					// is emmited for PBKDF2-HMAC-SHA{256,384,512}
					: (err.name === "InvalidAccessError")
						? pbkdf2_js.apply(self, args)
						: Promise.reject(err));
	};
}();