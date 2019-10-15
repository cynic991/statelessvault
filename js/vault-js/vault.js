/**** Stateless Vault by Andrea Guerini is licensed under the Creative Commons Attribution 4.0 International License. 
To view a copy of this license, visit http://creativecommons.org/licenses/by/4.0/. 
Based on works by Maarten Billemont (https://github.com/Lyndir/MasterPassword/) 
and by Tom Thorogood (https://github.com/tmthrgd/mpw-js). ****/

// This is a modified version of https://github.com/tmthrgd/mpw-js/blob/master/mpw.js
/* This algorithm produces different generated passwords. On one hand, it tries to improve entropy */
/* and strength on brute force attack; on the other hand, it semplifies structure and discards unused code */

/* class to create user Object. It stores temporarily user's personal data: name and password */
class USER {
	/* Object's constructor receives name and password as input */
	constructor(name, password) {
		
		/* Store name on the object, this is not used at all internally */
		this.name = name;
		
		/* Calculate the master key which will be used to calculate the password seed */
		this.key = USER.calculateKey(name, password);
	}
	
	/* The static keyword defines a static method for a class. Static methods aren't called on instances */
	/* of the class. Instead, they're called on the class itself. These are often utility functions, such */
	/* as functions to create or clone objects. */
	/* This static method calls calculateKey function for input name and password.*/
	static calculateKey(name, password) {
		if (!name || !name.length) {				/* if name is false (there is no name) or name's length is false*/
			/* The Promise.reject() method returns a Promise object that is rejected with a given reason.*/
			/* the reason is a new Error because user didn't type a name*/
			return Promise.reject(new Error("full name not present")); 
		}
		
		if (!password || !password.length) { /* if password is false (there is no name) or password's length is false*/
			/* The Promise.reject() method returns a Promise object that is rejected with a given reason.*/
			/* the reason is a new Error because user didn't type secret password*/
			return Promise.reject(new Error("secret password not present"));
		}
		
		/* The try...catch statement marks a block of statements to try, and specifies a response, */
		/* should an exception be thrown. */
		try {
			
			/* IE, Opera Mini and Edge until version 75 don't support textEncoder and encode*/
			/* These browsers produce the catched exception. Stateless Vault can't work with these browsers. */
			/* try to convert password string to a Uint8Array w/ UTF-8*/
			password = USER.textEncoder.encode(password);			
  
			/* IE, Opera Mini and Edge until version 75 don't support textEncoder and encode*/
			/* These browsers produce the catched exception. Stateless Vault can't work with these browsers. */
			/* The TextEncoder.prototype.encode() method takes a USVString as input, and returns a Uint8Array */
			/* containing the text given in parameters encoded with the specific method for that TextEncoder object.*/
			/* USVString corresponds to the set of all possible sequences of unicode scalar values. */
			/* The Uint8Array typed array represents an array of 8-bit unsigned integers. */
			// try to convert name string to a Uint8Array w/ UTF-8
			name = USER.textEncoder.encode(name);

			/* IE, Opera Mini and Edge until version 75 don't support textEncoder and encode*/
			/* These browsers produce the catched exception. Stateless Vault can't work with these browsers. */
			// Convert USER.NS string to a Uint8Array w/ UTF-8
			let NS = USER.textEncoder.encode(USER.NS);
					
			/* In cryptography, a salt is random data that is used as an additional input to a one-way */
			/* function that "hashes" data, a password or passphrase. 
			/* The Uint8Array typed array represents an array of 8-bit unsigned integers. */
			// Create salt array and a DataView representing it
			var salt = new Uint8Array(									/*new array of 8-bit unsigned integers (length is the input)*/
				NS.length																	/*length of NS + 4 + length of name */
				+ 4/*sizeof(uint32)*/ + name.length
			);
			/* The let statement declares a block scope local variable */
			/* The DataView view provides a low-level interface for reading and writing multiple number */
			/* types in a binary ArrayBuffer, without having to care about the platform's endianness.   */
			/* "Endian" and "endianness" (or "byte-order") describe how computers organize the bytes that */
			/* make up numbers. */
			/* salt.buffer is used as storage backing the new DataView object.*/
			/* salt.byteOffset: the offset, in bytes, to the first byte in the above buffer for the new  */
			/* view to reference.*/
			/* salt.byteLength: the number of elements in the byte array. */
			let saltView = new DataView(salt.buffer, salt.byteOffset, salt.byteLength);
			let i = 0;
			
			/* Array.set() is an inbuilt method and is used to set a specified value to a */
			/* specified index of a given object array. */
			// Set salt[0,] to NS: salt[0] = NS
			salt.set(NS, i); 
			i = i + NS.length;
			
			// Set salt[i,i+4] to name.length UINT32 in big-endian form
			/* The setUint32() method stores an unsigned 32-bit integer (unsigned long) value at the */
			/* specified byte offset from the start of the DataView. */
			/* dataview.setUint32(byteOffset, value [, littleEndian]) */
			/* i = The offset, in byte, from the start of the view where to store the data. */
			/* nome.length = The value to set. */
			/* false: 32-bit integer is stored in big-endian format */
			saltView.setUint32(i, name.length, false/*big-endian*/); 
			i = i + 4/*sizeof(uint32)*/;
			
			// Set salt[i,] to name: salt[NS.length] = name
			salt.set(name, i); 
			i = i + name.length;
			
			/* It catches exceptions thrown by try block. If there's an exception, it returns a Promise object */
			/* that is rejected with a given reason. */
		} catch (e) {
			return Promise.reject(e);
		}
		
		/* The let statement declares a block scope local variable */
		// Derive the master key (see scrypt.js)
		// why is buflen 64*8==512==r*buflen
		// key will have the result of window.scrypt
		// Inputs are password, salt, n=32768, r=8, p=2, buflen=64
		let key = window.scrypt(password, salt, 32768/*= n*/, 8/*= r*/, 2/*= p*/, 64/*= buflen*/);
		
		/* The conditional (ternary) operator is the only JavaScript operator that takes three operands. */
		/* This operator is frequently used as a shortcut for the if statement. */
		/* condition ? exprIfTrue : exprIfFalse */
		// If the Web Crypto API is supported import the key, otherwise return
		return window.crypto.subtle
			? key.then(  
		/* The then() method returns a Promise. It takes up to two arguments: callback functions for the */
		/* success and failure cases of the Promise. p.then(onFulfilled[, onRejected]); */
		/* An arrow function expression => is a syntactically compact alternative to a regular function expression,*/
		/* although without its own bindings to the this, arguments, super, or new.target keywords. Arrow function */
		/* expressions are still suited as methods, and they cannot be used as constructors. */
				// 1st argument: Import the key into WebCrypto to use later with sign while
				// being non-extractable
		/* The importKey() method of the SubtleCrypto interface imports a key: that is, it takes as input a key  */
		/* in an external, portable format and gives you a CryptoKey object that you can use in the Web Crypto API.*/
		/* Inputs. raw:"In this format the key is supplied as an ArrayBuffer containing the raw bytes for the key. */
		/* key is key data defined before, name "HMAC" and SHA-256 are algorithm information, false defines  */
		/* that is not extractable so the key can't be exported, ["sign"] defines usage */
				key => window.crypto.subtle.importKey("raw", key, {
					name: "HMAC",
					hash: {
						name: "SHA-256"
					}
				}, false/*not extractable*/, [ "sign" ])/*= key*/
			)
			/* return kay data if Web Crypto API is not supported */
			: key;
	}
	
	/* calculateSeed receives as input parameters: site, 1, null and USER.NS. */
	calculateSeed(site, counter = 1, context = null, NS = USER.NS) {
		/* if site is false (there's no site's name) */
		if (!site) {
			/* It returns a rejected Promise with a new error about site's name absence */
			return Promise.reject(new Error("insert URI or site name"));
		}
		
		/* if counter is out of range, it returns error. This can't happen according idenx.html */
		if (counter < 1 || counter > 4294967295/*Math.pow(2, 32) - 1*/) {
			return Promise.reject(new Error("counter out of range (0 - 2^32)"));
		}
		
		/* The try...catch statement marks a block of statements to try, and specifies a response, */
		/* should an exception be thrown. */
		try {
			
			/* IE, Opera Mini and Edge until version 75 don't support textEncoder and encode*/
			/* These browsers produce the catched exception. Stateless Vault can't work with these browsers. */
			/* The TextEncoder.prototype.encode() method takes a USVString as input, and returns a Uint8Array */
			/* containing the text given in parameters encoded with the specific method for that TextEncoder object.*/
			/* USVString corresponds to the set of all possible sequences of unicode scalar values. */
			/* The Uint8Array typed array represents an array of 8-bit unsigned integers. */
			// Convert site string to a Uint8Array w/ UTF-8
			site = USER.textEncoder.encode(site);
			
			// Convert NS string to a Uint8Array w/ UTF-8
			NS = USER.textEncoder.encode(NS);
			
			if (context) { /* if context is true (there is context) */
				// Convert context string to a Uint8Array w/ UTF-8
				context = USER.textEncoder.encode(context);
			}
			
			/* The DataView view provides a low-level interface for reading and writing multiple number */
			/* types in a binary ArrayBuffer, without having to care about the platform's endianness.   */
			/* "Endian" and "endianness" (or "byte-order") describe how computers organize the bytes that */
			/* make up numbers. */
			// Create data array (input is array length) and a DataView representing it
			var data = new Uint8Array(
				NS.length
				+ 4/*sizeof(uint32)*/ + site.length
				+ 4/*sizeof(int32)*/
				+ (context																/* if context is true, it adds 4 + context.length */
					? 4/*sizeof(uint32)*/ + context.length	/* otherwise it adds 0 */
					: 0)
			);
			/* data.buffer is used as storage backing the new DataView object.*/
			/* data.byteOffset: the offset, in bytes, to the first byte in the above buffer for the new  */
			/* view to reference.*/
			/* data.byteLength: the number of elements in the byte array. */
			/* The let statement declares a block scope local variable */
			let dataView = new DataView(data.buffer, data.byteOffset, data.byteLength);
			let i = 0;
			
			/* Array.set() is an inbuilt method and is used to set a specified value to a */
			/* specified index of a given object array. */
			// Set data[0,] to NS: data[0]=NS
			data.set(NS, i); 
			i = i + NS.length;
			
			/* The setUint32() method stores an unsigned 32-bit integer (unsigned long) value at the */
			/* specified byte offset from the start of the DataView. */
			/* dataview.setUint32(byteOffset, value [, littleEndian]) */
			/* i = NS.length: offset, in byte, from the start of the view where to store the data. */
			/* site.length = the value to set. */
			/* false: 32-bit integer is stored in big-endian format */
			// Set data[i,i+4] to site.length UINT32 in big-endian form
			dataView.setUint32(i, site.length, false/*big-endian*/); 
			i = i + 4/*sizeof(uint32)*/;
			
			// Set data[i,] to site: data[i]=site, i=NS.length+4
			data.set(site, i); 
			i = i + site.length;
			
			/* i = NS.length+4+site.length: offset, in byte, from the start of the view where to store the data. */
			/* counter = the value to set. */
			/* false: 32-bit integer is stored in big-endian format */
			// Set data[i,i+4] to counter INT32 in big-endian form
			dataView.setInt32(i, counter, false/*big-endian*/); 
			i = i + 4/*sizeof(int32)*/;
			
			if (context) {			/*if context is true (there's context) */
				/* i = NS.length+4+site.length+4: offset, in byte, from the start of the view where to store the data.*/
				/* context.length = the value to set. */
				/* false: 32-bit integer is stored in big-endian format */
				// Set data[i,i+4] to context.length UINT32 in big-endian form
				dataView.setUint32(i, context.length, false/*big-endian*/); 
				i = i + 4/*sizeof(uint32)*/;
				
				// Set data[i,] to context: data[i]=context, where i = NS.length+4+site.length+4+4
				data.set(context, i); 
				i = i + context.length;
			}
		
		/* It catches exceptions thrown by try block. If there's an exception, it returns a Promise object */
		/* that is rejected with a given reason. */
		} catch (e) {
			return Promise.reject(e);
		}
		
		//it return current key
		return this.key.then(
		/* The then() method returns a Promise. It takes up to two arguments: callback functions for the */
		/* success and failure cases of the Promise. p.then(onFulfilled[, onRejected]); */
		/* An arrow function expression => is a syntactically compact alternative to a regular function expression,*/
			/* If success, it signs data using HMAC-SHA-256 w/ this.key */
			/* The sign() method of the SubtleCrypto interface generates a digital signature. */		
			/* crypto.subtle.sign(algorithm, key, data);*/
			/* algorithm is HMAC-SHA-256 */
			/* key is a CryptoKey object containing the key to be used for signing.*/
			/* data is an ArrayBuffer or ArrayBufferView object containing the data to be signed. */
			key => window.crypto.subtle.sign({									
				name: "HMAC",											 
				hash: {
					name: "SHA-256"
				}
			}, key, data)/*= seed*/
		).then(	
			// If success, it converts the seed to Uint8Array from ArrayBuffer
			seed => new Uint8Array(seed)/*= seed*/
		);
	}
	
	// generate function
	generate(site, counter = 1, context = null, template = "long", NS = USER.NS) {
		// Does the requested template exist?
		if (!(template in USER.templates)) { /* if there's no that template, return a rejected promise with a new error */
			return Promise.reject(new Error("argument template invalid"));
		}
		
		/* Calculate the seed with current values of site, counter, context and NS */
		let seed = this.calculateSeed(site, counter, context, NS);
		
		/* The then() method returns a Promise. It takes up to two arguments: callback functions for the */
		/* success and failure cases of the Promise. p.then(onFulfilled[, onRejected]); */
		return seed.then(function (seed) { /* If success, input data is seed */
			// Find the selected template array
			template = USER.templates[template];
			
			/* Select the specific template based on seed[0]. Index for template is seed[0] module length of template */
			template = template[seed[0] % template.length];
			
			// Split the template string (e.g. xxx...xxx)
			/* The map() method creates a new array with the results of calling a provided function on every element */
			/* in the calling array. */
			return template.split("").map(function (c, i) {
				// Use USER.passchars to map the template string (e.g. xxx...xxx)
				// to characters (e.g. c -> bcdfghjklmnpqrstvwxyz)
				let chars = USER.passchars[c];  /* chars è il carattere avente di USER.passchars avente indice c */
				
				/* Select the character using seed[i + 1] module length of chars */
				return chars[seed[i + 1] % chars.length];
			}).join("");  															/* At the end every characters is joined with each other */
		});																						/* Here GENERATED PASSWORD is calculated */
	}
	
	// generate a password with the password namespace
	generatePassword(site, counter = 1, template = "long") {
		return this.generate(site, counter, null, template, USER.PasswordNS);
	}
	
	// generate a security answer with the answer namespace
	generateAnswer(site, counter = 1, context = "", template = "phrase") {
		return this.generate(site, counter, context, template, USER.AnswerNS);
	}
	
	invalidate() {
		// Replace this.key w/ a Promise.reject
		// Preventing all future access
		this.key = Promise.reject(new Error("invalid state"));
	}
}

// A TextEncoder in UTF-8 to convert strings to `Uint8Array`s
USER.textEncoder = new TextEncoder;

// The namespace used in calculateKey
USER.NS = "it.unimi.statelessvault";

// The namespaces used in calculateSeed
USER.PasswordNS = "it.unimi.statelessvault.login";
USER.AnswerNS   = "it.unimi.statelessvault.answer";

// The templates that passwords may be created from
// The characters map to USER.passchars
USER.templates = {
  // 32 characters: letters, numbers and symbols
	maximum: [
		"xnoxxnxAzxzxxxzxxxxAxxxnxzxozxxz",
		"xxxxnxxxxoxxxxxxxaxxxxAnxxxxnozx",
    "xxxzxzaxxxxxxAxxxzxxxzxxxoxxxnaz",
    "xoxxxxxnxAxzxxzxxxxnoxaxxxaxxxxz",
    "xxxxxoxzxzxxxCxxxzxoxxxAxxxoxzxa"
	],
  // 20 characters: letters, numbers and symbols
	long: [
		"avcxvnoCxxvcvaxvcvxx",
		"avxcvCxvxcvnxoCxvcvx",
		"axvcvCvcxvCxvxcvxnxo",
		"avcxcnoxCvcxxxvCxvcv",
		"avxccCxxvcvnoCxxvxcv",
		"avcxcxCvcxvCxvcvnxxo",
		"avcvnoCvcxxxcCvcvxxx",
		"avxcvCvxxxccnoxCxvcv",
		"axxvcvxCvccCxvcvxxno",
		"avcxvnxoxCxvcvxxCvcc",
		"axvxcxvxCxvcvnxoCvcc",
		"avcvxCvcxxvxCvccxxno",
		"avccnoCvxcxcxCxvxcxv",
		"axvxccCvccnxxoxxCvcv",
		"avccCxxvccxxCvcxxvno",
		"avcxxvnoxxCvccxxCvcc",
		"avcxxvCvxzccnoCxxvcc",
		"axvcvCvcxcxxCvccnoxx",
		"axxvccnoxCvxcvCvcxxc",
		"avxccCxxxvcvxnoCxxvc",
		"avcxcCvxcxxvCvxccxxn"
	],
  // 12 characters: letters, numbers and symbols
	medium: [
		"CacnoxxxxCvc",
		"CacCxxxxvcno",
    "CaxxoxCnnxxx"
	],
  // 8 characters: letters, numbers and symbols
  light: [
    "zvnanona",
    "zVnCaCan",
    "znoaCcCo"
  ],
  // 8 characters: letters and numbers
	basic: [
		"aaanaaan",
		"aannaaan",
		"aaannaaa"
	],
  // 4 characters: letters and numbers
	short: [
		"Cvcn",
    "NCnc",
    "xnCc",
    "mcCa"
	],
  // 4 numbers
	pin: [
		"nnnn",
    "nNnN",
    "mnNm",
    "nmmN"
	],
  // 6 numbers
  pin6: [
    "nmnNnN",
    "nnnnnn",
    "NnNmnn",
    "mNnmmN"
  ],
  // 8 numbers
  pin8: [
    "mNnmNnm",
    "NnnmNnm",
    "nmnNnNm",
    "nnnnnnn"
  ],
	phrase: [
		"cvcc cvc cvccvcv cvc",
		"cvc cvccvcvcv cvcv",
		"cv cvccv cvc cvcvccv"
	]
};

// The password character mapping
// c in template becomes bcdfghjklmnpqrstvwxyz
USER.passchars = {
	V: "AEIOU",
	C: "BCDFGHJKLMNPQRSTVWXYZ",
	v: "aeiou",
	c: "bcdfghjklmnpqrstvwxyz",
	A: "AEIOUBCDFGHJKLMNPQRSTVWXYZ",
	a: "AEIOUaeiouBCDFGHJKLMNPQRSTVWXYZbcdfghjklmnpqrstvwxyz",
  N: "01234",
  m: "56789",
	n: "0123456789",
	o: "@&%?,=[]_:-+*$£#!'^;()/.\|{}<>°",
  z: "AEIOUaeiouBCDFGHJKLMNPQRSTVWXYZbcdfghjklmnpqrstvwxyz0123456789",
	x: "AEIOUaeiouBCDFGHJKLMNPQRSTVWXYZbcdfghjklmnpqrstvwxyz0123456789@&%?,=[]_:-+*$£#!'^;()/.\|{}<>°",
	" ": " "
};
