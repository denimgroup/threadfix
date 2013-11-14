package com.denimgroup.threadfix.framework.engine;

import java.io.File;

import com.denimgroup.threadfix.framework.enums.FrameworkType;
import com.denimgroup.threadfix.framework.enums.SourceCodeAccessLevel;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

public class ProjectConfig {

	private final FrameworkType frameworkType;
	private final SourceCodeAccessLevel sourceCodeAccessLevel;
	private final File rootFile;
	private final String urlPathRoot;
	
	public ProjectConfig(@NotNull FrameworkType frameworkType,
                         @NotNull SourceCodeAccessLevel sourceCodeAccessLevel,
                         @Nullable File rootFile,
                         @Nullable String urlPathRoot) {
		this.frameworkType = frameworkType;
		this.sourceCodeAccessLevel = sourceCodeAccessLevel;
		this.rootFile = rootFile;
		this.urlPathRoot = urlPathRoot;
	}

    @NotNull
	public FrameworkType getFrameworkType() {
		return frameworkType;
	}

    @NotNull
	public SourceCodeAccessLevel getSourceCodeAccessLevel() {
		return sourceCodeAccessLevel;
	}

    @Nullable
	public File getRootFile() {
		return rootFile;
	}

    @Nullable
	public String getUrlPathRoot() {
		return urlPathRoot;
	}
}
