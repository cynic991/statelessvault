/*** Stateless Vault by Andrea Guerini is licensed under the Creative Commons Attribution 4.0 International License. 
To view a copy of this license, visit http://creativecommons.org/licenses/by/4.0/. 
Based on works by Maarten Billemont (https://github.com/Lyndir/MasterPassword/) 
and by Tom Thorogood (https://github.com/tmthrgd/mpw-js).  ***/

// Test for required ES6 features
// Use an eval call to avoid a hard-fail on ES5 parsers.
var ES6 = false;
var esdir = "es5/";
try {
    // Use ES6 code if the ES6 class, let, destructive assignment and rest arguments are supported.
    eval("class $ES6 { constructor() { let b = true; this.b = b; } } var [ES6, esdir] = ((...args) => args)(new $ES6().b, '')");
} catch (e) {
}

// If crypto.subtle is not supported, try crypto.webkitSubtle instead.
if (window.crypto && !window.crypto.subtle && window.crypto.webkitSubtle)
    window.crypto.subtle = window.crypto.webkitSubtle;
if ((!window.crypto || !window.crypto.subtle) && window.SubtleCrypto)
    window.crypto = { subtle: window.SubtleCrypto }

// If Web Crypto API is not supported we include a JS crypto library
// https://code.google.com/p/crypto-js/
//Disabled by default.  Enable manually if your browser requires this.
/*if (!window.crypto || !window.crypto.subtle) {
    document.write("<script src='https://cdnjs.cloudflare.com/ajax/libs/crypto-js/3.1.9-1/rollups/hmac-sha256.js'><\/script>");
    document.write("<script src='https://cdnjs.cloudflare.com/ajax/libs/crypto-js/3.1.9-1/hmac-sha3.js'></script>");
    document.write("<script src='https://cdnjs.cloudflare.com/ajax/libs/crypto-js/3.1.9-1/rollups/pbkdf2.js'><\/script>");
    document.write("<script src='https://cdnjs.cloudflare.com/ajax/libs/crypto-js/3.1.9-1/components/lib-typedarrays-min.js'><\/script>");
}*/

if (!Number.MAX_SAFE_INTEGER)
    Number.MAX_SAFE_INTEGER = Math.pow(2, 53) - 1;

// If Typed Arrays are not supported we include the polyfill
// https://github.com/inexorabletash/polyfill
window.ArrayBuffer || document.write("<script src=js/typedarray-polyfill.js><\/script>");
	
// If Promise is not supported we include the polyfill
// https://github.com/taylorhakes/promise-polyfill
window.Promise || document.write("<script src=js/promise-polyfill.js><\/script>");

// If setImmediate is not implemented we include the polyfill
window.setImmediate || document.write("<script src=js/" + esdir + "setImmediate-polyfill.js><\/script>");

// Include the scrypt implementation
document.write("<script src=js/" + esdir + "vault-js/pbkdf2.js><\/script>");
document.write("<script src=js/" + esdir + "vault-js/scrypt.js?1><\/script>");

// Include the USER class
document.write("<script src=js/" + esdir + "vault-js/vault.js?1><\/script>");
