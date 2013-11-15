////////////////////////////////////////////////////////////////////////
//
//     Copyright (c) 2009-2013 Denim Group, Ltd.
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
package com.denimgroup.threadfix.service.merge;

import java.io.File;

import com.denimgroup.threadfix.data.entities.Application;
import com.denimgroup.threadfix.framework.engine.ProjectConfig;
import com.denimgroup.threadfix.framework.engine.ServletMappings;
import com.denimgroup.threadfix.framework.enums.FrameworkType;
import com.denimgroup.threadfix.framework.enums.SourceCodeAccessLevel;

/**
 * This class is used to hold information about what types of algorithms to use in a vulnerability merge.
 * 
 * @author mcollins
 *
 */
public class ScanMergeConfiguration extends ProjectConfig {
	
	private SourceCodeAccessLevel sourceCodeAccessLevel;
	private FrameworkType frameworkType;
	private Application application;
	private final File workTree;
	private final ServletMappings servletMappings;
	
	public ScanMergeConfiguration(SourceCodeAccessLevel sourceCodeAccessLevel,
			FrameworkType frameworkType,
			File workTree,
			Application application,
			ServletMappings servletMappings) {
		super(frameworkType, sourceCodeAccessLevel, workTree, "/" + getApplicationRoot(application));
		this.frameworkType = frameworkType;
		this.sourceCodeAccessLevel  = sourceCodeAccessLevel;
		this.workTree = workTree;
		this.application = application;
		this.servletMappings = servletMappings;
	}
	
	public Application getApplication() {
		return application;
	}
	
	public String getApplicationRoot() {
		return getApplicationRoot(application);
	}
	
	private static String getApplicationRoot(Application application) {
		if (application != null) {
			return application.getProjectRoot();
		} else {
			return null;
		}
	}

	public File getWorkTree() {
		return workTree;
	}

	public ServletMappings getServletMappings() {
		return servletMappings;
	}

	@Override
	public SourceCodeAccessLevel getSourceCodeAccessLevel() {
		return sourceCodeAccessLevel;
	}

	@Override
	public FrameworkType getFrameworkType() {
		return frameworkType;
	}
}
