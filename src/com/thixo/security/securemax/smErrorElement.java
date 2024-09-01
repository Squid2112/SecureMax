package com.thixo.security.securemax;

/**
 * <p>
 * Title: Squid Security Systems
 * </p>
 *
 * <p>
 * Description: Ultimate Java Security for ColdFusion
 * </p>
 *
 * <p>
 * Copyright: Copyright (c) 2005
 * </p>
 *
 * @author Jeff L Greenwell
 * @version 1.0
 */

public class smErrorElement {

    public static final int smNoError = 0;
    public static final int smError = 1;
    public static final int smWarning = 2;

    public int ErrorType;
    public String ErrorReason;
    public String ExceptionMessage;

    public smErrorElement(int Type, String Reason, String Message) {
        this.ErrorType = Type;
        this.ErrorReason = new String(Reason);
        this.ExceptionMessage = new String(Message);
    }
}
