package com.chrisdisdero.crdcrypt;

import android.support.test.runner.AndroidJUnit4;

import org.junit.Test;
import org.junit.runner.RunWith;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;

import static org.junit.Assert.*;

/**
 * Instrumentation tests of the classes {@link CRDCrypt} and {@link CRDCryptException}.
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
@RunWith(AndroidJUnit4.class)
public class CRDCryptTests {

    @Test
    public void testEncryptNullKeyNullBytes() throws Exception {

        boolean firedException = false;
        try {

            CRDCrypt.aes256Encrypt(null, null);

        } catch (CRDCryptException e) {

            firedException = e.getMessage().compareToIgnoreCase("specified key is null or empty") == 0;
        }

        assertTrue("expected exception not fired", firedException);
    }

    @Test
    public void testEncryptEmptyKeyNullBytes() throws Exception {

        boolean firedException = false;
        try {

            CRDCrypt.aes256Encrypt("", null);

        } catch (CRDCryptException e) {

            firedException = e.getMessage().compareToIgnoreCase("specified key is null or empty") == 0;
        }

        assertTrue("expected exception not fired", firedException);
    }

    @Test
    public void testEncryptValidKeyNullBytes() throws Exception {

        byte[] encrypted = CRDCrypt.aes256Encrypt("This is my master key", null);
        assertNull("expected null encryption", encrypted);
    }

    @Test
    public void testEncryptValidKeyEmptyBytes() throws Exception {

        byte[] encrypted = CRDCrypt.aes256Encrypt("This is my master key", new byte[]{});
        assertNotNull("expected non-null encryption", encrypted);
        assertEquals("expected empty encryption", 0, encrypted.length);
    }

    @Test
    public void testDecryptNullKeyNullBytes() throws Exception {

        boolean firedException = false;
        try {

            CRDCrypt.aes256Decrypt(null, null);

        } catch (CRDCryptException e) {

            firedException = e.getMessage().compareToIgnoreCase("specified key is null or empty") == 0;
        }

        assertTrue("expected exception not fired", firedException);
    }

    @Test
    public void testDecryptEmptyKeyNullBytes() throws Exception {

        boolean firedException = false;
        try {

            CRDCrypt.aes256Decrypt("", null);

        } catch (CRDCryptException e) {

            firedException = e.getMessage().compareToIgnoreCase("specified key is null or empty") == 0;
        }

        assertTrue("expected exception not fired", firedException);
    }

    @Test
    public void testDecryptValidKeyNullBytes() throws Exception {

        byte[] decrypted = CRDCrypt.aes256Decrypt("This is my master key", null);
        assertNull("expected null encryption", decrypted);
    }

    @Test
    public void testDecryptValidKeyEmptyBytes() throws Exception {

        byte[] decrypted = CRDCrypt.aes256Decrypt("This is my master key", new byte[]{});
        assertNotNull("expected non-null encryption", decrypted);
        assertEquals("expected empty encryption", 0, decrypted.length);
    }

    @Test
    public void testBasicEncryptDecryptNoIV() throws Exception {

        String key = "This is my master key.";
        String expected = "Blippo the wonder dog.";

        byte[] encrypted = CRDCrypt.aes256Encrypt(key, expected.getBytes("UTF-8"));
        byte[] decrypted = CRDCrypt.aes256Decrypt(key, encrypted);
        String actual = new String(decrypted, "UTF-8");

        assertEquals("decrypted is not expected", expected, actual);
    }

    @Test
    public void testBasicEncryptDecryptEmptyIV() throws Exception {

        String key = "This is my master key.";
        String expected = "Blippo the wonder dog.";

        byte[] encrypted = CRDCrypt.aes256Encrypt(key, expected.getBytes("UTF-8"), new byte[]{});
        byte[] decrypted = CRDCrypt.aes256Decrypt(key, encrypted, new byte[]{});
        String actual = new String(decrypted, "UTF-8");

        assertEquals("decrypted is not expected", expected, actual);
    }

    @Test
    public void testBasicEncryptDecryptWithIV() throws Exception {

        String key = "This is my master key.";
        String expected = "Blippo the wonder dog.";

        byte[] iv1 = CRDCrypt.generateInitializationVector();

        byte[] encrypted1 = CRDCrypt.aes256Encrypt(key, expected.getBytes("UTF-8"), iv1);
        byte[] decrypted1 = CRDCrypt.aes256Decrypt(key, encrypted1, iv1);
        String actual = new String(decrypted1, "UTF-8");

        assertEquals("decrypted is not expected", expected, actual);

        byte[] iv2 = CRDCrypt.generateInitializationVector();

        byte[] encrypted2 = CRDCrypt.aes256Encrypt(key, expected.getBytes("UTF-8"), iv2);
        byte[] decrypted2 = CRDCrypt.aes256Decrypt(key, encrypted2, iv2);
        actual = new String(decrypted2, "UTF-8");

        assertEquals("decrypted is not expected", expected, actual);
        assertNotEquals("different initialization vector results in same encryption", encrypted1, encrypted2);

        byte[] decrypted3 = CRDCrypt.aes256Decrypt(key, encrypted1, iv2);
        actual = new String(decrypted3, "UTF-8");

        assertNotEquals("decryption with wrong initialization vector should be unequal", expected, actual);
    }

    @Test
    public void testUTF16EBasic() throws Exception {
        String key = "This is my master key.";
        String value = "This is my value.";
        byte[] expected = value.getBytes(StandardCharsets.UTF_16LE);
        String expectedMessage = new String(expected, StandardCharsets.UTF_16LE);

        byte[] encrypted = CRDCrypt.aes256Encrypt(key, expected, null);
        String encryptedMessage = new String(encrypted, StandardCharsets.UTF_16LE);
        byte[] decrypted = CRDCrypt.aes256Decrypt(key, encrypted, null);
        String decryptedMessage = new String(decrypted, StandardCharsets.UTF_16LE);

        assertFalse("encrypted bytes should be equal to decrypted bytes", Arrays.equals(encrypted, decrypted));
        assertNotEquals("encrypted string should not be equal to decrypted string", encryptedMessage, decryptedMessage);
        assertTrue("decrypted bytes are not equal to expected bytes", Arrays.equals(expected, decrypted));
        assertEquals("decrypted string is not equal to expected string", expectedMessage, decryptedMessage);
   }
}
