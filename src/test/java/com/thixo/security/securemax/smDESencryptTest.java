package com.thixo.security.securemax;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import javax.crypto.SecretKey;
import javax.crypto.KeyGenerator;
import java.security.NoSuchAlgorithmException;

import static org.junit.jupiter.api.Assertions.*;

public class smDESencryptTest {

    private smDESencrypt desEncryptWithKey;
    private smDESencrypt desEncryptWithPassphrase;
    private SecretKey secretKey;
    private final String passPhrase = "mySecurePassphrase";
    private final String testString = "This is a test string.";

    @BeforeEach
    public void setUp() throws NoSuchAlgorithmException {
        // Generate a DES key
        KeyGenerator keyGen = KeyGenerator.getInstance("DES");
        keyGen.init(56); // DES uses a 56-bit key size
        secretKey = keyGen.generateKey();

        // Initialize smDESencrypt with the key
        desEncryptWithKey = new smDESencrypt(secretKey, "DES");

        // Initialize smDESencrypt with the passphrase
        desEncryptWithPassphrase = new smDESencrypt(passPhrase);
    }

    @Test
    public void testEncryptAndDecryptWithKey() {
        String encrypted = desEncryptWithKey.encrypt(testString);
        assertNotNull(encrypted, "Encryption should return a non-null string.");

        String decrypted = desEncryptWithKey.decrypt(encrypted);
        assertNotNull(decrypted, "Decryption should return a non-null string.");
        assertEquals(testString, decrypted, "Decrypted string should match the original.");
    }

    @Test
    public void testEncryptAndDecryptWithPassphrase() {
        String encrypted = desEncryptWithPassphrase.encrypt(testString);
        assertNotNull(encrypted, "Encryption should return a non-null string.");

        String decrypted = desEncryptWithPassphrase.decrypt(encrypted);
        assertNotNull(decrypted, "Decryption should return a non-null string.");
        assertEquals(testString, decrypted, "Decrypted string should match the original.");
    }

    @Test
    public void testTripleDESEncryptAndDecrypt() {
        String encrypted = smDESencrypt.TripleDESencrypt(passPhrase, testString);
        assertNotNull(encrypted, "Encryption should return a non-null string.");

        String decrypted = smDESencrypt.TripleDESdecrypt(passPhrase, encrypted);
        assertNotNull(decrypted, "Decryption should return a non-null string.");
        assertEquals(testString, decrypted, "Decrypted string should match the original.");
    }
}
