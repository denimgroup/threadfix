////////////////////////////////////////////////////////////////////////
//
//     Copyright (c) 2009-2016 Denim Group, Ltd.
//
//     The contents of this file are subject to the Mozilla Public License
//     Version 2.0 (the "License"); you may not use this file except in
//     compliance with the License. You may obtain a copy of the License at
//     http://www.mozilla.org/MPL/
//
//     Software distributed under the License is distributed on an "AS IS"
//     basis, WITHOUT WARRANTY OF ANY KIND, either express or implied. See the
//     License for the specific language governing rights and limitations
//     under the License.
//
//     The Original Code is ThreadFix.
//
//     The Initial Developer of the Original Code is Denim Group, Ltd.
//     Portions created by Denim Group, Ltd. are Copyright (C)
//     Denim Group, Ltd. All Rights Reserved.
//
//     Contributor(s): Denim Group, Ltd.
//
////////////////////////////////////////////////////////////////////////

package com.denimgroup.threadfix.framework.engine;

import java.io.File;

import com.denimgroup.threadfix.data.enums.FrameworkType;
import com.denimgroup.threadfix.data.enums.SourceCodeAccessLevel;
import javax.annotation.Nonnull;
import javax.annotation.Nullable;

public class ProjectConfig {

	private final FrameworkType frameworkType;
	private final SourceCodeAccessLevel sourceCodeAccessLevel;
	private final File rootFile;
	private final String urlPathRoot;
	
	public ProjectConfig(@Nonnull FrameworkType frameworkType,
                         @Nonnull SourceCodeAccessLevel sourceCodeAccessLevel,
                         @Nullable File rootFile,
                         @Nullable String urlPathRoot) {
		this.frameworkType = frameworkType;
		this.sourceCodeAccessLevel = sourceCodeAccessLevel;
		this.rootFile = rootFile;
		this.urlPathRoot = urlPathRoot;
	}

    @Nonnull
	public FrameworkType getFrameworkType() {
		return frameworkType;
	}

    @Nonnull
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
