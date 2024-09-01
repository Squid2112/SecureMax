package com.thixo.security.securemax;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

public class smErrorElementTest {

    @Test
    public void testConstructor() {
        int type = smErrorElement.smError;
        String reason = "Sample Reason";
        String message = "Sample Message";

        smErrorElement errorElement = new smErrorElement(type, reason, message);

        assertEquals(type, errorElement.ErrorType, "ErrorType should be initialized correctly.");
        assertEquals(reason, errorElement.ErrorReason, "ErrorReason should be initialized correctly.");
        assertEquals(message, errorElement.ExceptionMessage, "ExceptionMessage should be initialized correctly.");
    }
}
