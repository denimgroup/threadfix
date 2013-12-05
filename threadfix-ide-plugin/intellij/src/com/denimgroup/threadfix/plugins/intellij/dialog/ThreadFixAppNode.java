package com.denimgroup.threadfix.plugins.intellij.dialog;

import com.intellij.ui.CheckedTreeNode;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

/**
 * Created with IntelliJ IDEA.
 * User: mac
 * Date: 12/5/13
 * Time: 11:24 AM
 * To change this template use File | Settings | File Templates.
 */
public class ThreadFixAppNode extends CheckedTreeNode {

    @NotNull
    public String getName() {
        return name;
    }

    @Nullable
    public String getId() {
        return id;
    }

    private String name, id;

    public ThreadFixAppNode(@NotNull String name, @Nullable String id) {
        this.name = name;
        this.id = id;
    }

}
