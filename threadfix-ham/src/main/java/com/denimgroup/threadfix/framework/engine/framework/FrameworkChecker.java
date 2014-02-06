package com.denimgroup.threadfix.framework.engine.framework;

import com.denimgroup.threadfix.data.enums.FrameworkType;
import com.denimgroup.threadfix.framework.engine.ProjectDirectory;
import org.jetbrains.annotations.NotNull;

public abstract class FrameworkChecker {

    @NotNull
    public abstract FrameworkType check(@NotNull ProjectDirectory directory);

    @Override
    public int hashCode() {
        return this.getClass().getName().hashCode();
    }

    @Override
    public boolean equals(Object other) {
        return other instanceof FrameworkChecker && this.hashCode() == other.hashCode();
    }

}
