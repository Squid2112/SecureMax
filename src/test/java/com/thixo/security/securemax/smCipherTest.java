package com.thixo.security.securemax;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

import java.nio.charset.StandardCharsets;

public class smCipherTest {

    private smCipher cipher;

    @BeforeEach
    public void setUp() {
        cipher = new smCipher();
    }

    @Test
    public void testEncipherAndDecipher() {
        String originalText = "This is a test of the encryption and decryption.";
        byte[] originalBytes = originalText.getBytes(StandardCharsets.UTF_8);

        // Encrypt the data
        byte[] encryptedBytes = cipher.EncipherData(originalBytes);
        assertNotNull(encryptedBytes);
        assertNotEquals(originalText, new String(encryptedBytes, StandardCharsets.ISO_8859_1));

        // Decrypt the data
        byte[] decryptedBytes = cipher.DecipherData(encryptedBytes);
        assertNotNull(decryptedBytes);
        String decryptedText = new String(decryptedBytes, StandardCharsets.UTF_8);

        // Trim any padding null bytes (if any)
        decryptedText = smUtils.Trim00(decryptedText);

        // Assert that the original and decrypted texts are equal
        assertEquals(originalText, decryptedText);
    }

    @Test
    public void testEmptyInput() {
        byte[] emptyBytes = new byte[0];

        // Encrypt the empty input
        byte[] encryptedBytes = cipher.EncipherData(emptyBytes);
        assertNotNull(encryptedBytes);
        assertEquals(0, encryptedBytes.length);

        // Decrypt the empty input
        byte[] decryptedBytes = cipher.DecipherData(encryptedBytes);
        assertNotNull(decryptedBytes);
        assertEquals(0, decryptedBytes.length);
    }

    @Test
    public void testDifferentEncipherDecipherResults() {
        String text1 = "First test string.";
        String text2 = "Second test string.";

        byte[] encryptedText1 = cipher.EncipherData(text1.getBytes(StandardCharsets.UTF_8));
        byte[] encryptedText2 = cipher.EncipherData(text2.getBytes(StandardCharsets.UTF_8));

        assertNotEquals(encryptedText1, encryptedText2);

        byte[] decryptedText1 = cipher.DecipherData(encryptedText1);
        byte[] decryptedText2 = cipher.DecipherData(encryptedText2);

        String resultText1 = new String(decryptedText1, StandardCharsets.UTF_8);
        String resultText2 = new String(decryptedText2, StandardCharsets.UTF_8);

        resultText1 = smUtils.Trim00(resultText1);
        resultText2 = smUtils.Trim00(resultText2);

        assertEquals(text1, resultText1);
        assertEquals(text2, resultText2);
    }

    @Test
    public void testEncipherDecipherWithBinaryData() {
        byte[] binaryData = new byte[] { 0x01, 0x23, 0x45, 0x67, (byte) 0x89, (byte) 0xAB, (byte) 0xCD, (byte) 0xEF };

        byte[] encryptedData = cipher.EncipherData(binaryData);
        assertNotNull(encryptedData);
        assertNotEquals(binaryData, encryptedData);

        byte[] decryptedData = cipher.DecipherData(encryptedData);
        assertNotNull(decryptedData);

        assertArrayEquals(binaryData, decryptedData);
    }
}
