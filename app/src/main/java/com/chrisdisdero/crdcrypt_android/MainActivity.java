package com.chrisdisdero.crdcrypt_android;

import android.support.v7.app.AppCompatActivity;
import android.os.Bundle;
import android.util.Log;

import com.chrisdisdero.crdcrypt.CRDCrypt;
import com.chrisdisdero.crdcrypt.CRDCryptException;

import java.io.UnsupportedEncodingException;

/**
 * Example use in an Android activity of CRDCrypt library - a quick way to encrypt/decrypt strings with AES256 on Android.
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
public class MainActivity extends AppCompatActivity {

    //region Private members

    private final static String TAG = MainActivity.class.getCanonicalName();

    //endregion

    @Override
    protected void onCreate(Bundle savedInstanceState) {

        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        /* Example use of CRDCrypt */

        // Key to use for encrypting/decrypting should be stored securely.
        String myKey = "TheThirtyTwoByteKeyForEncryption";

        // Create an initialization vector to use for encrypting and decrypting the same data.  Store this with the encrypted data.
        byte[] initializationVector = null;
        try {

            initializationVector = CRDCrypt.generateInitializationVector();

        } catch (CRDCryptException e) {

            Log.e(TAG, "onCreate: failed to create initialization vector", e);
        }

        // Encrypt some data
        String dataToEncrypt = "This is the data to encrypt with AES256 encryption.";
        byte[] encrypted = null;
        try {

            encrypted = CRDCrypt.aes256Encrypt(myKey, dataToEncrypt.getBytes("UTF-8"), initializationVector);

        } catch (UnsupportedEncodingException e) {

            Log.e(TAG, "onCreate: failed to encode data to encrypt", e);

        } catch (CRDCryptException e) {

            Log.e(TAG, "onCreate: failed to encrypt data", e);
        }

        // Decrypt the encrypted data
        byte[] decrypted = null;
        try {

            decrypted = CRDCrypt.aes256Decrypt(myKey, encrypted, initializationVector);

        } catch (CRDCryptException e) {

            Log.e(TAG, "onCreate: failed to decrypt data", e);
        }

        // Get the string from the decrypted data.
        String transformedData = null;
        try {

            transformedData = new String(decrypted, "UTF-8");

        } catch (UnsupportedEncodingException e) {

            Log.e(TAG, "onCreate: failed to decode decrypted data to string", e);
        }

        // Decrypted data should be the same as the original data encrypted.
        if (transformedData.equals(dataToEncrypt)) {

            Log.i(TAG, "onCreate: SUCCESS! decrypted data is equal to original data.");

        } else {

            Log.e(TAG, "onCreate: FAILED! decrypted data is not equal to original data");
        }
    }
}
