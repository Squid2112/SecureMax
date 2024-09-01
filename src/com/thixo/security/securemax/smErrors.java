package com.thixo.security.securemax;

/**
 * <p>Title: Squid Security Systems</p>
 * @author Jeff L Greenwell
 * @version 1.0
 */

import com.thixo.security.securemax.smErrorElement;
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
