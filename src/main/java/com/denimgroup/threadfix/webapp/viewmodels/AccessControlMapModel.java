package com.denimgroup.threadfix.webapp.viewmodels;

import java.util.List;

public class AccessControlMapModel {

	private List<Integer> applicationIds;
	private boolean allApps;
	private Integer teamId, roleId, userId;
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

}
