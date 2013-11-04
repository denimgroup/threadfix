package com.denimgroup.threadfix.framework.engine;

import java.io.File;

import com.denimgroup.threadfix.framework.enums.FrameworkType;
import com.denimgroup.threadfix.framework.enums.SourceCodeAccessLevel;

public class ProjectConfig {

	private final FrameworkType frameworkType;
	private final SourceCodeAccessLevel sourceCodeAccessLevel;
	private final File rootFile;
	private final String urlPathRoot;
	
	public ProjectConfig(FrameworkType frameworkType,
			SourceCodeAccessLevel sourceCodeAccessLevel,
			File rootFile,
			String urlPathRoot) {
		this.frameworkType = frameworkType;
		this.sourceCodeAccessLevel = sourceCodeAccessLevel;
		this.rootFile = rootFile;
		this.urlPathRoot = urlPathRoot;
	}

	public FrameworkType getFrameworkType() {
		return frameworkType;
	}

	public SourceCodeAccessLevel getSourceCodeAccessLevel() {
		return sourceCodeAccessLevel;
	}

	public File getRootFile() {
		return rootFile;
	}
	
	public String getUrlPathRoot() {
		return urlPathRoot;
	}
}
