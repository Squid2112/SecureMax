package com.thixo.security.securemax;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

public class smUtilsTest {

    @Test
    public void testTrim00WithString() {
        assertNull(smUtils.Trim00((String) null), "Trim00 should return null when input is null.");
        
        assertEquals("", smUtils.Trim00(""), "Trim00 should return an empty string when input is an empty string.");

        assertEquals("Hello", smUtils.Trim00("Hello"), "Trim00 should return the same string if no trailing 0x00.");

        assertEquals("Hello", smUtils.Trim00("Hello\u0000"), "Trim00 should trim one trailing 0x00 character.");

        assertEquals("Hello", smUtils.Trim00("Hello\u0000\u0000\u0000"), "Trim00 should trim multiple trailing 0x00 characters.");
    }

    @Test
    public void testTrim00WithBytes() {
        assertNull(smUtils.Trim00((byte[]) null), "Trim00 should return null when input is null.");
        
        assertArrayEquals(new byte[0], smUtils.Trim00(new byte[0]), "Trim00 should return an empty array when input is an empty array.");

        byte[] data = "Hello".getBytes();
        assertArrayEquals(data, smUtils.Trim00(data), "Trim00 should return the same array if no trailing 0x00.");

        byte[] dataWithNull = "Hello\u0000".getBytes();
        assertArrayEquals("Hello".getBytes(), smUtils.Trim00(dataWithNull), "Trim00 should trim one trailing 0x00 byte.");

        byte[] dataWithMultipleNulls = "Hello\u0000\u0000\u0000".getBytes();
        assertArrayEquals("Hello".getBytes(), smUtils.Trim00(dataWithMultipleNulls), "Trim00 should trim multiple trailing 0x00 bytes.");
    }
}
