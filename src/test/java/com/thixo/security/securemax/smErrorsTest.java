package com.thixo.security.securemax;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

public class smErrorsTest {

    private smErrors errors;

    @BeforeEach
    public void setUp() {
        errors = new smErrors();
    }

    @Test
    public void testAddError() {
        assertTrue(errors.ErrorList.isEmpty(), "Error list should be empty initially.");

        errors.AddError(smErrorElement.smError, "Reason 1", "Message 1");
        assertEquals(1, errors.ErrorList.size(), "Error list should contain one error.");
        assertEquals(smErrorElement.smError, errors.ErrorList.get(0).ErrorType, "Error type should match.");
        assertEquals("Reason 1", errors.ErrorList.get(0).ErrorReason, "Error reason should match.");
        assertEquals("Message 1", errors.ErrorList.get(0).ExceptionMessage, "Error message should match.");

        errors.AddError(smErrorElement.smWarning, "Reason 2", "Message 2");
        assertEquals(2, errors.ErrorList.size(), "Error list should contain two errors.");
    }

    @Test
    public void testReset() {
        errors.AddError(smErrorElement.smError, "Reason 1", "Message 1");
        errors.AddError(smErrorElement.smWarning, "Reason 2", "Message 2");
        assertEquals(2, errors.ErrorList.size(), "Error list should contain two errors.");

        errors.Reset();
        assertTrue(errors.ErrorList.isEmpty(), "Error list should be empty after reset.");
    }
}
