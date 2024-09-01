package com.thixo.security.securemax;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

public class smCRC32Test {

    private smCRC32 crc32;

    @BeforeEach
    public void setUp() {
        crc32 = new smCRC32();
    }

    @Test
    public void testToIntWithBytes() {
        byte[] data = "Test string".getBytes();
        long expectedCRC = calculateCRC32(data);
        assertEquals(expectedCRC, crc32.toInt(data));
    }

    @Test
    public void testToIntWithString() {
        String data = "Test string";
        long expectedCRC = calculateCRC32(data.getBytes());
        assertEquals(expectedCRC, crc32.toInt(data));
    }

    @Test
    public void testToHexTrigWithBytes() {
        byte[] data = "Test string".getBytes();
        String result = crc32.toHexTrig(data);
        assertNotNull(result);
        assertTrue(result.matches("[0-9A-Z]+"), "The result should be a valid base-36 string.");
    }

    @Test
    public void testToHexTrigWithString() {
        String data = "Test string";
        String result = crc32.toHexTrig(data);
        assertNotNull(result);
        assertTrue(result.matches("[0-9A-Z]+"), "The result should be a valid base-36 string.");
    }

    @Test
    public void testToHexWithBytes() {
        byte[] data = "Test string".getBytes();
        String result = crc32.toHex(data);
        assertNotNull(result);
        assertTrue(result.matches("[0-9A-F]{8}"));
    }

    @Test
    public void testToHexWithString() {
        String data = "Test string";
        String result = crc32.toHex(data);
        assertNotNull(result);
        assertTrue(result.matches("[0-9A-F]{8}"));
    }

    @Test
    public void testToBase64WithBytes() {
        byte[] data = "Test string".getBytes();
        String result = crc32.toBase64(data);
        assertNotNull(result);
        assertFalse(result.isEmpty());
    }

    @Test
    public void testToBase64WithString() {
        String data = "Test string";
        String result = crc32.toBase64(data);
        assertNotNull(result);
        assertFalse(result.isEmpty());
    }

    @Test
    public void testSetAndGetEncoding() {
        String newEncoding = "ISO-8859-1";
        crc32.setEncoding(newEncoding);
        assertEquals(newEncoding, crc32.getEncoding());
    }

    private long calculateCRC32(byte[] data) {
        java.util.zip.CRC32 crc32 = new java.util.zip.CRC32();
        crc32.update(data);
        return crc32.getValue();
    }
}
