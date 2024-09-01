package com.thixo.security.securemax;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

public class smThreaderTest {

    private smThreader threader;

    @BeforeEach
    public void setUp() {
        threader = new smThreader();
    }

    @Test
    public void testEnthreadAndDethread() {
        String key = "Brandon";
        String data = "Rice";

        byte[] threaded = threader.enthread(key.getBytes(), data.getBytes());
        assertNotNull(threaded, "Threaded result should not be null.");

        byte[][] dethreaded = threader.dethread(threaded);
        assertNotNull(dethreaded, "Dethreaded result should not be null.");
        assertEquals(2, dethreaded.length, "Dethreaded result should contain two arrays.");
        assertEquals(key, new String(dethreaded[0]), "The first dethreaded part should match the key.");
        assertEquals(data, new String(dethreaded[1]), "The second dethreaded part should match the data.");
    }

    @Test
    public void testEnthreadWithEmptyData() {
        String key = "Brandon";
        String data = "";

        byte[] threaded = threader.enthread(key.getBytes(), data.getBytes());
        assertNotNull(threaded, "Threaded result should not be null.");

        byte[][] dethreaded = threader.dethread(threaded);
        assertNotNull(dethreaded, "Dethreaded result should not be null.");
        assertEquals(2, dethreaded.length, "Dethreaded result should contain two arrays.");
        assertEquals(key, new String(dethreaded[0]), "The first dethreaded part should match the key.");
        assertEquals(data, new String(dethreaded[1]), "The second dethreaded part should be empty.");
    }

    @Test
    public void testSmEnthreadAndSmDethread() {
        String key = "Brandon";
        String data = "Rice";

        String threaded = threader.smEnthread(key, data);
        assertNotNull(threaded, "Threaded result should not be null.");

        String[] dethreaded = threader.smDethread(threaded);
        assertNotNull(dethreaded, "Dethreaded result should not be null.");
        assertEquals(2, dethreaded.length, "Dethreaded result should contain two parts.");
        assertEquals(key, dethreaded[0], "The first dethreaded part should match the key.");
        assertEquals(data, dethreaded[1], "The second dethreaded part should match the data.");
    }

    @Test
    public void testSmEnthreadWithInvalidEncoding() {
        threader.setEncoding("Invalid-Encoding");

        String result = threader.smEnthread("key", "data");
        assertEquals("ERROR: Unsupported Encoding [Invalid-Encoding]", result,
                "Result should indicate an unsupported encoding error.");
    }

    @Test
    public void testSetAndGetEncoding() {
        String newEncoding = "ISO-8859-1";
        threader.setEncoding(newEncoding);
        assertEquals(newEncoding, threader.getEncoding(), "Encoding should match the set value.");
    }

    @Test
    public void testEdgeCaseShortKeyAndData() {
        String key = "A";
        String data = "B";

        byte[] threaded = threader.enthread(key.getBytes(), data.getBytes());
        assertNotNull(threaded, "Threaded result should not be null.");

        byte[][] dethreaded = threader.dethread(threaded);
        assertNotNull(dethreaded, "Dethreaded result should not be null.");
        assertEquals(2, dethreaded.length, "Dethreaded result should contain two arrays.");
        assertEquals(key, new String(dethreaded[0]), "The first dethreaded part should match the key.");
        assertEquals(data, new String(dethreaded[1]), "The second dethreaded part should match the data.");
    }

    @Test
    public void testEdgeCaseLongKeyAndData() {
        String key = "ThisIsAReallyLongKeyForTesting";
        String data = "ThisIsAReallyLongDataForTesting";

        byte[] threaded = threader.enthread(key.getBytes(), data.getBytes());
        assertNotNull(threaded, "Threaded result should not be null.");

        byte[][] dethreaded = threader.dethread(threaded);
        assertNotNull(dethreaded, "Dethreaded result should not be null.");
        assertEquals(2, dethreaded.length, "Dethreaded result should contain two arrays.");
        assertEquals(key, new String(dethreaded[0]), "The first dethreaded part should match the key.");
        assertEquals(data, new String(dethreaded[1]), "The second dethreaded part should match the data.");
    }
}
