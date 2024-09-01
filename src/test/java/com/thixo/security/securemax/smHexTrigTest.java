package com.thixo.security.securemax;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

public class smHexTrigTest {

    private smHexTrig hexTrig;

    @BeforeEach
    public void setUp() {
        hexTrig = new smHexTrig();
    }

    @Test
    public void testEncodeWithString() {
        String input = "Test string for encoding";
        String encoded = hexTrig.encode(input);
        assertNotNull(encoded, "Encoded string should not be null.");
        assertFalse(hexTrig.isError, "isError should be false.");
    }

    @Test
    public void testEncodeWithBytes() {
        byte[] input = "Test string for encoding".getBytes();
        String encoded = hexTrig.encode(input);
        assertNotNull(encoded, "Encoded string should not be null.");
        assertFalse(hexTrig.isError, "isError should be false.");
    }

    @Test
    public void testDecodeValidString() {
        String input = "Test string for encoding";
        String encoded = hexTrig.encode(input);
        String decoded = hexTrig.decode(encoded);
        assertEquals(input, decoded, "Decoded string should match the original input.");
        assertFalse(hexTrig.isError, "isError should be false.");
    }

    @Test
    public void testDecodeInvalidString() {
        String invalidInput = "Invalid HexTrig string!";
        String decoded = hexTrig.decode(invalidInput);
        assertTrue(hexTrig.isError, "isError should be true for invalid input.");
        assertEquals("Invalid Hexatrigesimal Encoding", hexTrig.errorReason, "Error reason should indicate invalid encoding.");
        assertEquals("", decoded, "Decoded string should be empty for invalid input.");
    }

    @Test
    public void testSetAndGetEncoding() {
        String newEncoding = "ISO-8859-1";
        hexTrig.setEncoding(newEncoding);
        assertEquals(newEncoding, hexTrig.getEncoding(), "Encoding should match the set value.");
    }

    @Test
    public void testEncodingErrorHandling() {
        hexTrig.setEncoding("Invalid-Encoding");
        String encoded = hexTrig.encode("Test string");
        assertTrue(hexTrig.isError, "isError should be true for unsupported encoding.");
        assertEquals("Unsupported Encoding: Invalid-Encoding", hexTrig.errorReason, "Error reason should indicate unsupported encoding.");
        assertEquals("", encoded, "Encoded string should be empty for unsupported encoding.");
    }
}
