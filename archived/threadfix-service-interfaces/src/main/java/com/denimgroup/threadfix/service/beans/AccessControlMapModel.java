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

import java.util.List;

public class AccessControlMapModel {

	private List<Integer> applicationIds;
	private boolean allApps;
	private Integer teamId, roleId, userId, groupId;
	private List<String> roleIdMapList; // This is weird but I can't think of a better way to handle it
	
	public List<Integer> getApplicationIds() {
		return applicationIds;
	}

	public void setApplicationIds(List<Integer> applicationIds) {
		this.applicationIds = applicationIds;
	}

	public boolean isAllApps() {
		return allApps;
	}

	public void setAllApps(boolean allApps) {
		this.allApps = allApps;
	}

	public Integer getTeamId() {
		return teamId;
	}

	public void setTeamId(Integer teamId) {
		this.teamId = teamId;
	}

	public List<String> getRoleIdMapList() {
		return roleIdMapList;
	}

	public void setRoleIdMapList(List<String> roleIdMapList) {
		this.roleIdMapList = roleIdMapList;
	}

	public Integer getRoleId() {
		return roleId;
	}

	public void setRoleId(Integer roleId) {
		this.roleId = roleId;
	}

	public Integer getUserId() {
		return userId;
	}

	public void setUserId(Integer userId) {
		this.userId = userId;
	}
	
	public Integer getGroupId() {
		return groupId;
	}

	public void setGroupId(Integer groupId) {
		this.groupId = groupId;
	}

}
