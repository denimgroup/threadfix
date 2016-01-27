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
package com.denimgroup.threadfix.service.beans;

import com.denimgroup.threadfix.data.entities.Application;

public class ScanParametersBean {

	String applicationType, sourceCodeAccessLevel, sourceCodeUrl;
	
	public String getApplicationType() {
		return applicationType;
	}

	public void setApplicationType(String applicationType) {
		this.applicationType = applicationType;
	}

	public String getSourceCodeAccessLevel() {
		return sourceCodeAccessLevel;
	}

	public void setSourceCodeAccessLevel(String sourceCodeAccessLevel) {
		this.sourceCodeAccessLevel = sourceCodeAccessLevel;
	}

	public String getSourceCodeUrl() {
		return sourceCodeUrl;
	}

	public void setSourceCodeUrl(String sourceCodeUrl) {
		this.sourceCodeUrl = sourceCodeUrl;
	}
	
	public static ScanParametersBean getScanParametersBean(Application app) {
		ScanParametersBean returnBean = new ScanParametersBean();
		
		if (app != null) {
			returnBean.setApplicationType(app.getFrameworkTypeEnum().toString());
			returnBean.setSourceCodeAccessLevel(app.getSourceCodeAccessLevelEnum().toString());
			returnBean.setSourceCodeUrl(app.getRepositoryUrl());
		}
	
		return returnBean;
	}
	
}
