# CRDCrypt-Android

[![Release](https://jitpack.io/v/cdisdero/CRDCrypt-Android.svg)](https://jitpack.io/#cdisdero/CRDCrypt-Android)

Simple straightforward library for AES 256 bit encryption/decryption of data for Android projects.

- [Overview](#overview)
- [Requirements](#requirements)
- [Installation](#installation)
- [Usage](#usage)
- [Conclusion](#conclusion)
- [License](#license)

## Overview
This code library provides a simple way to encrypt and decrypt data using the AES 256 bit encryption algorithm.  The library also allows you to create an initialization vector that can be used when encrypting/decrypting to provide extra security in the encrypted bytes by making the byte patterns less recognizable between encryptions of similar data.

## Requirements
- Android API 16 or higher
- Android Studio 3.3.1+
- Java 1.8+

## Installation
You can simply copy the following files from the GitHub tree into your app project:

  * `CRDCrypt.java`
    - Class providing a static interface to the methods for creating an initialization vector, and encoding and decoding data.

  * `CRDCryptException.java`
    - Class that provides a single exception type for CRDCrypt methods.

### JitPack
Alternatively, you can install it via [JitPack.io](https://jitpack.io/#cdisdero/CRDCrypt-Android)

To integrate CRDCrypt into your Android Studio app project, add the following to your root build.gradle at the end of repositories:

```
	allprojects {
		repositories {
			...
			maven { url 'https://jitpack.io' }
		}
	}
```

Then, add this dependency to your app build.gradle file:

```
	dependencies {
		compile 'com.github.cdisdero:CRDCrypt-Android:1.0.2'
	}
```

## Usage
The library is easy to use.  There is an example of usage in the sample app main activity code file `MainActivity.java`.  Just import the CRDCrypt and CRDCryptException classes and use the method provided to generate a new initialization vector:

```
import com.chrisdisdero.crdcrypt.CRDCrypt;
import com.chrisdisdero.crdcrypt.CRDCryptException;

...

// Create an initialization vector to use for encrypting and decrypting the same data.  Store this with the encrypted data.
byte[] initializationVector = null;
try {

    initializationVector = CRDCrypt.generateInitializationVector();

} catch (CRDCryptException e) {

    Log.e(TAG, "onCreate: failed to create initialization vector", e);
}

```

Then, to encrypt some data, you need a 32 byte key and the initialization vector you just created:

```
String myKey = "TheThirtyTwoByteKeyForEncryption";

String dataToEncrypt = "This is the data to encrypt with AES256 encryption.";

byte[] encrypted = null;
try {

    encrypted = CRDCrypt.aes256Encrypt(myKey, dataToEncrypt.getBytes("UTF-8"), initializationVector);

} catch (UnsupportedEncodingException e) {

    Log.e(TAG, "onCreate: failed to encode data to encrypt", e);

} catch (CRDCryptException e) {

    Log.e(TAG, "onCreate: failed to encrypt data", e);
}
```

You can encrypt and decrypt data with no initialization vector as well.

It's important to use the same key and initialization vector you used to encrypt the data when you need to decrypt the data:

```
byte[] decrypted = null;
try {

    decrypted = CRDCrypt.aes256Decrypt(myKey, encrypted, initializationVector);

} catch (CRDCryptException e) {

    Log.e(TAG, "onCreate: failed to decrypt data", e);
}
```

It's a good idea to store both the initialization vector and the encrypted data together in the same data store.  Keep the key you use somewhere else secure.

## Conclusion
I hope this small library is helpful to you in your next Android project.  I'll be updating as time and inclination permits and of course I welcome all your feedback.

## License
CRDCrypt is released under an Apache 2.0 license. See LICENSE for details.
