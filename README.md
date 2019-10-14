# statelessvault
HTML5 password wallet

Stateless Vault by Andrea Guerini is licensed under a Creative Commons Attribution 4.0 International License
Based on works by Marteen Billemont (https://github.com/tmthrgd/mpw-js) and Tom Thorogood (https://github.com/Lyndir/MasterPassword/tree/master/platform-independent/web-js). 
This project was born for academic purposes and it was developed to accomplish Mobile and Web Programming course. Its author is a student of Computer and Network Security, Bachelor Level, University of Milan.

Stateless Vault is a password wallet that generates passwords locally.
No personal data, like your passwords, are sent to any server or stored permanently.
The encryption algorithms use HASH cryptographic functions to generate unique and strong passwords.
They need three information: your full name, one secret password and a site name.
This web application can be stored in your application cache to use it off-line.
It should work on every updated browser, even future Edge releases, except IE and Opera Mini.
Read more and discover how it works. 

STATELESSNESS AND RESPONSABILITY
Stateless Vault is a password wallet that generates passwords locally. Key principles of Stateless Vault are statelessness and responsability. There's no real encrypted vault, so there's no sign in or login and personal data, like your name or your passwords, are not sent or stored to any server. The name Stateless Vault is an oxymoron because in real life every kind of vault has a state. State is the technical term for "what needs to be saved". Your storage support or a cloud won't have an encrypted file and they won't manage encrypted communication over the internet. So vulnerable surface is reduced and risks upon state protection disappear. Breaking your hard drive, losing your device or breaching against your cloud provider will not affect your passwords.

But warning, user is totally responsible for management of his passwords. In fact stateless operations imply that an algorithm can give you what you need based on nothing more than input you can give. Input information are determinant to calculate always the same expected generated passwords. Don't forget the following input information.

INPUT INFORMATION
Stateless Vault requires three pieces of information that user must remember. The following rules are recommended.

First information is your full name, as it's written on your ID card or passport. This information could be exposed. The strength of the encryption is not based on it, but it's necessary for calculation.
Second information is a unique, personal and secret password . This information must be rembered without saving it or writing it anywhere. A good secret password could be a nonsense phrase. The strength of Stateless Vault generation process is based on it. Take your time for thinking a unique, easy to remember and strong secret password.
Third information is about where you need to be authenticated. It could be the URI where you want to login, it could be site's name of the service, it could be the name of the service itself, it could be the name of a physical device. It's up to you. Our suggestion: choose a way for all your generated password and mantain it beacause you must remember it.
Optional fourth information: a numeric value between 1 and 100. This number allows user to change generated password. Stateless Vault shows a counter to input this numeric value and the default value is 1. User should increase default value when he wants to modify generated password only (for exemple, after a fixed period of time) without modifying his unique secret password. The site counter ensures you can easily create new password for the site if that password were compromised.
Thanks to these information you'll be always able to generate the same passwords because Stateless Vault doesn't store any data about your name, your secret passwords or your sites. It's based on mathematics. An addition, for example 1 + 2 + 3, will always give the same result, in our example 6. You can try it on every calculator and it will be 6 every time. At the same way, Stateless Vault uses input information to calculate always the same generated passwords. Every working browser (except Internet Explorer, Opera Mini and current version of Microsoft Edge) will produce your passwords.

LIGHTNESS AND OFF-LINE USE
Stateless Vault uses your Application Cache (AppCache) to run its web application offline. So Stateless Vault will be loaded and work correctly even if users click the refresh button when they are offline. There are some advantages: offline passwords recovering, speed and reduced server load. After your first connection to the web application, you'll be able to calculate your generated passwords every time you want on the same browser regardless you are online or offline.
Stateless Vault is light because there are no personal data to store. In your Application Cache Stateless Vault will occupy no more than 300 KB. This is suitable even for device with small storage capacity.

Moreover, you can also add this web application to your home screen, as a standalone web app. Discover how to do it. This is a easy way to access Stateless Vault directly from your smartphone or desktop without opening your browser, but this is not a real app. In this case you won't be able to access Stateless Vault offline. It's just a shortcut. Offline use works only on web browsers.

CRYPTOGRAPHIC ALGORITHMS
Identity
Your identity is defined by your unique secret password. This unlocks all your doors. Your input [name] is necessary for identification. Your input [secret password] is a prove of knowledge to authenticate your identity and represents the key. Together, they create a cryptographic identifier that is unique to every authenticated user. We call this union Master Criptographic Key. The SCRYPT cryptographic function is employed to derive a 64-byte Master Cryptographic Key from the user’s [name] and [secret password] using a fixed set of parameters. Fixed parameters are: N = 32768, r = 8 and p = 2 and scope (see Key scopes and templates) are chosen according to time and resources consumption.
masterKey = SCRYPT( key, seed, N, r, p, dkLen )
key = [secret password]
seed = scope . LEN([name]) . [name]
N = 32768
r = 8
p = 2
dkLen = 64
To know more about SCRYPT Criptographic Algorithm see Stronger Key Derivation Via Sequential Memory-Hard Functions.

Site key
Your site key is a derivative from your secret key when it is used to unlock the door to a specific site. Your site key is the result of three components: your [site name], your Master Cryprographic Key (see Identity) and your [site counter]. Your Master Cryptographic Key establishes a unique string of bits to create your site passwords. The site counter ensures you can easily create new password for the site if that password were compromised. Together, they create a cryptographic identifier that is unique to your account at a given site. The HMAC-SHA-256 cryptographic function to derive a 64-byte Cryptographic Site Key from the site name and Master Cryptographic Key scoped to a given counter value.

siteKey = HMAC-SHA-256 (key, seed)
key = [master key]
seed = scope . LEN([site name]) . [site name] . [counter]
To know more about HMAC-SHA-256 see Secure Hash Standard and The Keyed-Hash Message Authentication Code.

Site password
Your site password is an identifier derived from your site key in compilance with the site password policy and user's will. The purpose of this step is to render the site's cryptographic key into a format that the site password input will accept and user can be relaxed about strength against dictonary or brute force attack. Stateless Vault declares ten site password formats and uses pre-defined password "templates" to render site key legible composed by letters, numbers or symbols. The template is resolved to generate password from site key's first byte. When the selected template is selected, it is used to translate site key bytes into password characters. The result is a site password in the form defined by the site template scoped to our site key. Finally the generated password can be used to authenticate user for his account at the given site.

template = templates [ siteKey[0] % LEN( templates ) ]

for i in 0..LEN( template )
passChars = templateChars [ template[i] ]
passWord[i] = passChars[ site key[i+1] % LEN( passChars )]

Key scopes and templates
Stateless Vault algorithm defines several key scopes. These scopes are used to scope the key generation to a specific purpose. These purpose are defined:

The authentication scope is used when genrating a key that is used for authenticating the user, such as a password.
Authentication scope identifier = it.unimi.statelessvault
The identification scope is used when generating a key that is intended for the purpose of identifying the user.
Identification scope identifier = it.unimi.statelessvault.login
The recovery scope is used for generating fall-back identifiers for use in access recovery when the primary authentication mechanism has failed.
Recovery scope identifier = it.unimi.statelessvault.answer
Stateless Vault defines ten password templates to make a best-effort attempt at generating site passwords that adheres to accepted formats by websites and ensures memorability of chosen format, while also keeping its output entropy as high as possible under the constraints.

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
Stateless Vault template is a string of characters, where each character identifies a certain character class. As such, the template spesificies that the output password should be formed by substituing each of the template's character class charcters by a chosen character from character class.

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
}
