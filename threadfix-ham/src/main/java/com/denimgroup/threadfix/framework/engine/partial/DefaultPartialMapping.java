package com.denimgroup.threadfix.framework.engine.partial;

import com.denimgroup.threadfix.framework.enums.FrameworkType;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

public class DefaultPartialMapping implements PartialMapping {
	
	@Nullable
    private final String staticPath, dynamicPath, frameworkGuess;
	
	public DefaultPartialMapping(@Nullable String staticPath, @Nullable String dynamicPath, @Nullable String frameworkGuess) {
		this.staticPath = staticPath;
		this.dynamicPath = dynamicPath;
		this.frameworkGuess = frameworkGuess;
	}
	
	public DefaultPartialMapping(@Nullable String staticPath, @Nullable String dynamicPath) {
		this.staticPath = staticPath;
		this.dynamicPath = dynamicPath;
		this.frameworkGuess = null;
	}

	@Override
    @Nullable
	public String getStaticPath() {
		return staticPath;
	}

	@Override
    @Nullable
	public String getDynamicPath() {
		return dynamicPath;
	}

	@NotNull
    @Override
	public FrameworkType guessFrameworkType() {
		return FrameworkType.getFrameworkType(frameworkGuess);
	}

	@NotNull
    @Override
	public String toString() {
		return staticPath + " <--> " + dynamicPath;
	}
	
}
