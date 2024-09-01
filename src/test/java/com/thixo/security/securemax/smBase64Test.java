package com.thixo.security.securemax;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

import java.nio.charset.StandardCharsets;

public class smBase64Test {

    @BeforeEach
    public void setUp() {
        new smBase64();
    }

    @Test
    public void testEncodeString() {
        String input = "Hello, World!";
        String expected = "SGVsbG8sIFdvcmxkIQ==";
        String result = smBase64.encode(input);
        assertEquals(expected, result);
    }

    @Test
    public void testEncodeBytes() {
        byte[] input = "Hello, World!".getBytes(StandardCharsets.UTF_8);
        char[] result = smBase64.encode(input);
        String expected = "SGVsbG8sIFdvcmxkIQ==";
        assertEquals(expected, new String(result));
    }

    @Test
    public void testDecodeString() {
        String input = "SGVsbG8sIFdvcmxkIQ==";
        String expected = "Hello, World!";
        String result = smBase64.decode(input);
        assertEquals(expected, result);
    }

    @Test
    public void testDecodeBytes() {
        char[] input = "SGVsbG8sIFdvcmxkIQ==".toCharArray();
        byte[] result = smBase64.decode(input);
        String expected = "Hello, World!";
        assertEquals(expected, new String(result, StandardCharsets.UTF_8));
    }

    @Test
    public void testEncodeAndDecodeString() {
        String original = "This is a test of Base64 encoding and decoding.";
        String encoded = smBase64.encode(original);
        String decoded = smBase64.decode(encoded);
        assertEquals(original, decoded);
    }

    @Test
    public void testEncodeAndDecodeBytes() {
        byte[] original = "This is a test of Base64 encoding and decoding.".getBytes(StandardCharsets.UTF_8);
        char[] encoded = smBase64.encode(original);
        byte[] decoded = smBase64.decode(encoded);
        assertArrayEquals(original, decoded);
    }

    @Test
    public void testDecodeInvalidString() {
        String invalidBase64 = "Invalid base64 string!!";
        assertThrows(IllegalArgumentException.class, () -> smBase64.decode(invalidBase64));
    }

    @Test
    public void testDecodeInvalidBytes() {
        char[] invalidBase64 = "Invalid base64 string!!".toCharArray();
        assertThrows(IllegalArgumentException.class, () -> smBase64.decode(invalidBase64));
    }
}
