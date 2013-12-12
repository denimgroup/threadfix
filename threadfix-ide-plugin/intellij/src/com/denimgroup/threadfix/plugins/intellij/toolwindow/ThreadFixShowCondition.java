package com.denimgroup.threadfix.plugins.intellij.toolwindow;

import com.intellij.openapi.util.Condition;

/**
 * Created by mac on 12/12/13.
 */
public class ThreadFixShowCondition implements Condition {
    @Override
    public boolean value(Object o) {
        return true;
    }
}
