package com.denimgroup.threadfix.framework.engine.partial;

import com.denimgroup.threadfix.framework.enums.FrameworkType;

public class DefaultPartialMapping implements PartialMapping {
	
	private final String staticPath, dynamicPath, frameworkGuess;
	
	public DefaultPartialMapping(String staticPath, String dynamicPath, String frameworkGuess) {
		this.staticPath = staticPath;
		this.dynamicPath = dynamicPath;
		this.frameworkGuess = frameworkGuess;
	}
	
	public DefaultPartialMapping(String staticPath, String dynamicPath) {
		this.staticPath = staticPath;
		this.dynamicPath = dynamicPath;
		this.frameworkGuess = null;
	}

	@Override
	public String getStaticPath() {
		return staticPath;
	}

	@Override
	public String getDynamicPath() {
		return dynamicPath;
	}

	@Override
	public FrameworkType guessFrameworkType() {
		return FrameworkType.getFrameworkType(frameworkGuess);
	}

	@Override
	public String toString() {
		return staticPath + " <--> " + dynamicPath;
	}
	
}
