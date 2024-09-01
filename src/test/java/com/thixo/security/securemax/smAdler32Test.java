package com.thixo.security.securemax;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

import java.nio.charset.StandardCharsets;
import java.util.zip.Adler32;

public class smAdler32Test {

    private smAdler32 adler32;

    @BeforeEach
    public void setUp() {
        adler32 = new smAdler32();
    }

    @Test
    public void testRawAdler32WithBytes() {
        byte[] data = "Test string".getBytes(StandardCharsets.UTF_8);
        Adler32 expectedAdler = new Adler32();
        expectedAdler.update(data);
        long expected = expectedAdler.getValue();

        long result = adler32.rawAdler32(data);
        assertEquals(expected, result);
    }

    @Test
    public void testRawAdler32WithString() {
        String data = "Test string";
        Adler32 expectedAdler = new Adler32();
        expectedAdler.update(data.getBytes(StandardCharsets.UTF_8));
        long expected = expectedAdler.getValue();

        long result = adler32.rawAdler32(data);
        assertEquals(expected, result);
    }

    @Test
    public void testHexTrigAdler32WithBytes() {
        byte[] data = "Test string".getBytes(StandardCharsets.UTF_8);
        String result = adler32.hexTrigAdler32(data);
        assertNotNull(result);
        assertTrue(result.matches("[0-9A-Z]{8}"));
    }

    @Test
    public void testHexTrigAdler32WithString() {
        String data = "Test string";
        String result = adler32.hexTrigAdler32(data);
        assertNotNull(result);
        assertTrue(result.matches("[0-9A-Z]{8}"));
    }

    @Test
    public void testHexAdler32WithBytes() {
        byte[] data = "Test string".getBytes(StandardCharsets.UTF_8);
        String result = adler32.hexAdler32(data);
        assertNotNull(result);
        assertTrue(result.matches("[0-9A-F]{8}"));
    }

    @Test
    public void testHexAdler32WithString() {
        String data = "Test string";
        String result = adler32.hexAdler32(data);
        assertNotNull(result);
        assertTrue(result.matches("[0-9A-F]{8}"));
    }

    @Test
    public void testBase64Adler32WithBytes() {
        byte[] data = "Test string".getBytes(StandardCharsets.UTF_8);
        String result = adler32.base64Adler32(data);
        assertNotNull(result);
        assertFalse(result.isEmpty());
    }

    @Test
    public void testBase64Adler32WithString() {
        String data = "Test string";
        String result = adler32.base64Adler32(data);
        assertNotNull(result);
        assertFalse(result.isEmpty());
    }

    @Test
    public void testUnsupportedEncoding() {
        adler32.setEncoding("UNSUPPORTED-ENCODING");
        String result = adler32.hexAdler32("Test string");
        assertEquals("", result);
    }

    @Test
    public void testSetAndGetEncoding() {
        String newEncoding = "ISO-8859-1";
        adler32.setEncoding(newEncoding);
        assertEquals(newEncoding, adler32.getEncoding());
    }
}
