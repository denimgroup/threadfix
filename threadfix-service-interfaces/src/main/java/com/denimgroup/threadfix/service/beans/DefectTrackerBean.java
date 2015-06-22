////////////////////////////////////////////////////////////////////////
//
//     Copyright (c) 2009-2015 Denim Group, Ltd.
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

import javax.xml.bind.annotation.XmlRootElement;

@XmlRootElement
public class DefectTrackerBean {

	private int defectTrackerId;
	private String userName;
	private String password;
	private String projectName;
    private boolean useDefaultCredentials;

	@Override
	public String toString() {
		StringBuilder sb = new StringBuilder();
		sb.append("defectTrackerId: ").append(Integer.toString(getDefectTrackerId())).append(", ");
		sb.append("userName: ").append(getUserName()).append(", ");
		sb.append("password: ").append(getPassword()).append(", ");
		sb.append("projectName: ").append(getProjectName());
		return sb.toString();
	}

	public void setDefectTrackerId(int defectTrackerId) {
		this.defectTrackerId = defectTrackerId;
	}

	public int getDefectTrackerId() {
		return defectTrackerId;
	}

	public void setUserName(String userName) {
		this.userName = userName;
	}

	public String getUserName() {
		return userName;
	}

	public void setPassword(String password) {
		this.password = password;
	}

	public String getPassword() {
		return password;
	}

	public void setProjectName(String projectName) {
		this.projectName = projectName;
	}

	public String getProjectName() {
		return projectName;
	}

    public boolean isUseDefaultCredentials() {
        return useDefaultCredentials;
    }

    public void setUseDefaultCredentials(boolean useDefaultCredentials) {
        this.useDefaultCredentials = useDefaultCredentials;
    }
}