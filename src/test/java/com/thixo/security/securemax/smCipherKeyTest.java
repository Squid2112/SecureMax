package com.thixo.security.securemax;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

import java.util.HashSet;
import java.util.Set;

public class smCipherKeyTest {

    private smCipherKey cipherKey;

    @BeforeEach
    public void setUp() {
        cipherKey = new smCipherKey();
    }

    @Test
    public void testDefaultConstructor() {
        assertNotNull(cipherKey.keyBlock, "Key block should be initialized");
        assertEquals(4, cipherKey.keyBlock.length, "Key block should have 4 elements");
        assertTrue(cipherKey.isKeySet, "Key should be set after construction");
        assertUniqueKeyBlock(cipherKey.keyBlock);
    }

    @Test
    public void testConstructorWithKeyString() {
        String keyString = "TestKeyString";
        cipherKey = new smCipherKey(keyString);

        assertNotNull(cipherKey.keyBlock, "Key block should be initialized");
        assertEquals(4, cipherKey.keyBlock.length, "Key block should have 4 elements");
        assertTrue(cipherKey.isKeySet, "Key should be set after construction");
        assertNotEquals(0L, cipherKey.keyBlock[0], "Key block should be populated");
    }

    @Test
    public void testResetWithoutString() {
        long[] originalKeyBlock = cipherKey.keyBlock.clone();
        cipherKey.Reset();
        
        assertTrue(cipherKey.isKeySet, "Key should be set after reset");
        assertNotEquals(originalKeyBlock[0], cipherKey.keyBlock[0], "Key block should be updated after reset");
        assertUniqueKeyBlock(cipherKey.keyBlock);
    }

    @Test
    public void testResetWithKeyString() {
        String keyString = "AnotherTestKey";
        cipherKey.Reset(keyString);

        assertTrue(cipherKey.isKeySet, "Key should be set after reset");
        assertNotEquals(0L, cipherKey.keyBlock[0], "Key block should be populated after reset with string");
        assertUniqueKeyBlock(cipherKey.keyBlock);
    }

    @Test
    public void testBuildKeyWithShortString() {
        String shortKeyString = "Short";
        cipherKey.Reset(shortKeyString);

        assertTrue(cipherKey.isKeySet, "Key should be set after reset with short string");
        assertEquals(4, cipherKey.keyBlock.length, "Key block should have 4 elements");
        assertNotEquals(0L, cipherKey.keyBlock[0], "Key block should be populated after reset with short string");
    }

    private void assertUniqueKeyBlock(long[] keyBlock) {
        Set<Long> uniqueKeys = new HashSet<>();
        for (long key : keyBlock) {
            uniqueKeys.add(key);
        }
        assertEquals(4, uniqueKeys.size(), "Key block should have unique elements");
    }
}
