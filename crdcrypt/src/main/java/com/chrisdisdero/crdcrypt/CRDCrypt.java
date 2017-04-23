package com.chrisdisdero.crdcrypt;

import java.io.UnsupportedEncodingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * Simple and quick way to encrypt/decrypt strings with AES256 on Android.
 *
 * @author cdisdero.
 *
Copyright © 2017 Christopher Disdero.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
 */
public class CRDCrypt {

    //region Private members

    /**
     * Log tag for this class.
     */
    private static final String TAG = CRDCrypt.class.getCanonicalName();

    /**
     * Provider algorithm for use with initialization vector.
     */
    private static final String PROVIDER_IV = "AES/CBC/PKCS5Padding";

    /**
     * Provider algorithm for use without initialization vector.
     */
    private static final String PROVIDER_NO_IV = "AES/ECB/PKCS5Padding";

    //endregion

    //region Public methods

    /**
     * Generates a random initialization vector for use with {@link #aes256Decrypt(String, byte[], byte[])} or {@link #aes256Encrypt(String, byte[], byte[])}.
     *
     * @return The random initialization vector.
     *
     * @throws CRDCryptException
     */
    public static byte[] generateInitializationVector() throws CRDCryptException {

        SecureRandom random = new SecureRandom();
        Cipher cipher;
        try {

            cipher = Cipher.getInstance(PROVIDER_IV);

        } catch (NoSuchAlgorithmException e) {

            throw new CRDCryptException(TAG, "generateInitializationVector", "encryption algorithm not available", e);

        } catch (NoSuchPaddingException e) {

            throw new CRDCryptException(TAG, "generateInitializationVector", "padding algorithm not available", e);
        }

        byte[] realIV = new byte[cipher.getBlockSize()];
        random.nextBytes(realIV);
        return realIV;
    }

    /**
     * Encrypts the specified bytes with the key and optional initialization vector provided.
     *
     * @param key The key to use for encryption/decryption, should be the same key used for both.
     * @param decrypted The bytes to encrypt.
     * @param initializationVector The initialization vector provided by {@link #generateInitializationVector()}, or null if none used.
     *
     * @return The encrypted bytes.
     *
     * @throws CRDCryptException
     */
    public static byte[] aes256Encrypt(String key, byte[] decrypted, byte[] initializationVector) throws CRDCryptException {

        if (key == null || key.length() == 0) {

            throw new CRDCryptException(TAG, "aes256Encrypt", "specified key is null or empty");
        }

        if (decrypted == null || decrypted.length == 0) {

            // Nothing to do.
            return decrypted;
        }

        // Produce the hashed key for decryption based on the specified key.
        byte[] hashedKey;
        try {

            MessageDigest sha = MessageDigest.getInstance("SHA-256");
            hashedKey = sha.digest(key.getBytes("UTF-8"));

        } catch (NoSuchAlgorithmException e) {

            throw new CRDCryptException(TAG, "aes256Encrypt", "message digest algorithm not available", e);

        } catch (UnsupportedEncodingException e) {

            throw new CRDCryptException(TAG, "aes256Encrypt", "failed to encode key with UTF-8", e);
        }

        SecretKeySpec secretKeySpec;
        try {

            secretKeySpec = new SecretKeySpec(hashedKey, "AES");

        } catch (IllegalArgumentException e) {

            throw new CRDCryptException(TAG, "aes256Encrypt", "hashed key is invalid", e);
        }

        IvParameterSpec ivSpec = null;
        if (initializationVector != null && initializationVector.length > 0) {

            ivSpec = new IvParameterSpec(initializationVector);
        }

        // Encode the original data with AES
        Cipher cipher;
        if (ivSpec == null) {

            try {

                cipher = Cipher.getInstance(PROVIDER_NO_IV);

            } catch (NoSuchAlgorithmException e) {

                throw new CRDCryptException(TAG, "aes256Encrypt", "encryption algorithm not available", e);

            } catch (NoSuchPaddingException e) {

                throw new CRDCryptException(TAG, "aes256Encrypt", "padding algorithm not available", e);
            }

        } else {

            try {

                cipher = Cipher.getInstance(PROVIDER_IV);

            } catch (NoSuchAlgorithmException e) {

                throw new CRDCryptException(TAG, "aes256Encrypt", "encryption algorithm not available", e);

            } catch (NoSuchPaddingException e) {

                throw new CRDCryptException(TAG, "aes256Encrypt", "padding algorithm not available", e);
            }
        }

        try {

            cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, ivSpec);

        } catch (InvalidKeyException e) {

            throw new CRDCryptException(TAG, "aes256Encrypt", "invalid secret key spec", e);

        } catch (InvalidAlgorithmParameterException e) {

            throw new CRDCryptException(TAG, "aes256Encrypt", "invalid encryption parameter", e);
        }

        try {

            byte[] encodedBytes = cipher.doFinal(decrypted);
            return encodedBytes;

        } catch (IllegalBlockSizeException e) {

            throw new CRDCryptException(TAG, "aes256Encrypt", "illegal block size", e);

        } catch (BadPaddingException e) {

            throw new CRDCryptException(TAG, "aes256Encrypt", "invalid padding", e);
        }
    }

    /**
     * Encrypts the specified bytes with the key provided.
     *
     * @param key The key to use for encryption/decryption, should be the same key used for both.
     * @param decrypted The bytes to encrypt.
     *
     * @return The encrypted bytes.
     *
     * @throws CRDCryptException
     */
    public static byte[] aes256Encrypt(String key, byte[] decrypted) throws CRDCryptException {

        return aes256Encrypt(key, decrypted, null);
    }

    /**
     * Decrypts the specified encrypted bytes with the key and optional initialization vector provided.
     *
     * @param key The key to use for encryption/decryption, should be the same key used for both.
     * @param encrypted The bytes to decrypt.  Assumes it was previously encrypted with {@link #aes256Encrypt(String, byte[], byte[])}.
     * @param initializationVector The initialization vector provided by {@link #generateInitializationVector()}, or null if none used.  Should be the same initialization vector as used in {@link #aes256Encrypt(String, byte[], byte[])}.
     *
     * @return The decrypted bytes.
     *
     * @throws CRDCryptException
     */
    public static byte[] aes256Decrypt(String key, byte[] encrypted, byte[] initializationVector) throws CRDCryptException {

        if (key == null || key.length() == 0) {

            throw new CRDCryptException(TAG, "aes256Decrypt", "specified key is null or empty");
        }

        if (encrypted == null || encrypted.length == 0) {

            // Nothing to do.
            return encrypted;
        }

        // Produce the hashed key for decryption based on the specified key.
        byte[] hashedKey;
        try {

            MessageDigest sha = MessageDigest.getInstance("SHA-256");
            hashedKey = sha.digest(key.getBytes("UTF-8"));

        } catch (NoSuchAlgorithmException e) {

            throw new CRDCryptException(TAG, "aes256Decrypt", "message digest algorithm not available", e);

        } catch (UnsupportedEncodingException e) {

            throw new CRDCryptException(TAG, "aes256Decrypt", "failed to encode key with UTF-8", e);
        }

        SecretKeySpec secretKeySpec;
        try {

            secretKeySpec = new SecretKeySpec(hashedKey, "AES");

        } catch (IllegalArgumentException e) {

            throw new CRDCryptException(TAG, "aes256Decrypt", "hashed key is invalid", e);
        }

        IvParameterSpec ivSpec = null;
        if (initializationVector != null && initializationVector.length > 0) {

            ivSpec = new IvParameterSpec(initializationVector);
        }

        // Decode the encoded data with AES
        Cipher cipher;
        if (ivSpec == null) {

            try {

                cipher = Cipher.getInstance(PROVIDER_NO_IV);

            } catch (NoSuchAlgorithmException e) {

                throw new CRDCryptException(TAG, "aes256Decrypt", "encryption algorithm not available", e);

            } catch (NoSuchPaddingException e) {

                throw new CRDCryptException(TAG, "aes256Decrypt", "padding algorithm not available", e);
            }

        } else {

            try {

                cipher = Cipher.getInstance(PROVIDER_IV);

            } catch (NoSuchAlgorithmException e) {

                throw new CRDCryptException(TAG, "aes256Decrypt", "encryption algorithm not available", e);

            } catch (NoSuchPaddingException e) {

                throw new CRDCryptException(TAG, "aes256Decrypt", "padding algorithm not available", e);
            }
        }

        try {

            cipher.init(Cipher.DECRYPT_MODE, secretKeySpec, ivSpec);

        } catch (InvalidKeyException e) {

            throw new CRDCryptException(TAG, "aes256Decrypt", "invalid secret key spec", e);

        } catch (InvalidAlgorithmParameterException e) {

            throw new CRDCryptException(TAG, "aes256Decrypt", "invalid encryption parameter", e);
        }

        try {

            byte[] decodedBytes = cipher.doFinal(encrypted);
            return decodedBytes;

        } catch (IllegalBlockSizeException e) {

            throw new CRDCryptException(TAG, "aes256Decrypt", "illegal block size", e);

        } catch (BadPaddingException e) {

            throw new CRDCryptException(TAG, "aes256Decrypt", "invalid padding", e);
        }
    }

    /**
     * Decrypts the specified encrypted bytes with the key provided.
     *
     * @param key The key to use for encryption/decryption, should be the same key used for both.
     * @param encrypted The bytes to decrypt.  Assumes it was previously encrypted with {@link #aes256Encrypt(String, byte[], byte[])}.
     *
     * @return The decrypted bytes.
     *
     * @throws CRDCryptException
     */
    public static byte[] aes256Decrypt(String key, byte[] encrypted) throws CRDCryptException {

        return aes256Decrypt(key, encrypted, null);
    }
}
