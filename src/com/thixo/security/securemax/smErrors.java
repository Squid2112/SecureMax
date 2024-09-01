package com.thixo.security.securemax;

/**
 * <p>Title: Squid Security Systems</p>
 *
 * <p>Description: Ultimate Java Security for ColdFusion</p>
 *
 * <p>Copyright: Copyright (c) 2005</p>
 *
 * @author Jeff L Greenwell
 * @version 1.0
 */

import com.recruitmax.security.securemax.v1_0.smErrorElement;
import java.util.ArrayList;

public class smErrors {

    protected ArrayList ErrorList;

    public smErrors() {
        this.ErrorList = new ArrayList();
    }

    public void Reset() {
        int i = 0;
        while (!ErrorList.isEmpty())
            ErrorList.remove(0);
    }

    public void AddError(int Type, String Reason, String Message) {
        smErrorElement er = new smErrorElement(Type, Reason, Message);
        this.ErrorList.add(er);
    }
}
