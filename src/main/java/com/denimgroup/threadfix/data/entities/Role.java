////////////////////////////////////////////////////////////////////////
//
//     Copyright (c) 2009-2011 Denim Group, Ltd.
//
//     The contents of this file are subject to the Mozilla Public License
//     Version 1.1 (the "License"); you may not use this file except in
//     compliance with the License. You may obtain a copy of the License at
//     http://www.mozilla.org/MPL/
//
//     Software distributed under the License is distributed on an "AS IS"
//     basis, WITHOUT WARRANTY OF ANY KIND, either express or implied. See the
//     License for the specific language governing rights and limitations
//     under the License.
//
//     The Original Code is Vulnerability Manager.
//
//     The Initial Developer of the Original Code is Denim Group, Ltd.
//     Portions created by Denim Group, Ltd. are Copyright (C)
//     Denim Group, Ltd. All Rights Reserved.
//
//     Contributor(s): Denim Group, Ltd.
//
////////////////////////////////////////////////////////////////////////
package com.denimgroup.threadfix.data.entities;

import java.util.List;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.OneToMany;
import javax.persistence.Table;
import javax.validation.constraints.Size;

import org.codehaus.jackson.annotate.JsonIgnore;
import org.hibernate.validator.constraints.NotEmpty;

@Entity
@Table(name = "Role")
public class Role extends AuditableEntity {
	
	public enum Permissions {
		CAN_GENERATE_WAF_RULES, CAN_MANAGE_API_KEYS, CAN_MANAGE_APPLICATIONS, CAN_MANAGE_GROUPS, 
		CAN_MANAGE_REMOTE_PROVIDERS, CAN_MANAGE_ROLES, CAN_MANAGE_TEAMS, CAN_MANAGE_USERS, 
		CAN_MANAGE_WAFS, CAN_MODIFY_VULNERABILITIES, CAN_RUN_REPORTS, CAN_SUBMIT_DEFECTS, 
		CAN_UPLOAD_SCANS, CAN_VIEW_ERROR_LOGS, CAN_VIEW_JOB_STATUSES
	}
	
	public static final String ADMIN = "ROLE_ADMIN";
	public static final String USER = "ROLE_USER";
	
	public static final int NAME_LENGTH = 25;
	public static final int DISPLAY_NAME_LENGTH = 25;

	private static final long serialVersionUID = -1609499610449048270L;
	
	private Boolean canGenerateReports, canGenerateWafRules, canManageApiKeys, 
		canManageApplications, canManageGroups, canManageRemoteProviders, 
		canManageRoles, canManageTeams, canManageUsers, canManageWafs, 
		canModifyVulnerabilities, canSubmitDefects, canUploadScans, 
		canViewErrorLogs, canViewJobStatuses;
	
	private List<UserRoleMap> userRoleMaps;

	@NotEmpty(message = "{errors.required}")
	@Size(max = NAME_LENGTH, message = "{errors.maxlength}" + NAME_LENGTH)
	private String name;
	
	@NotEmpty(message = "{errors.required}")
	@Size(max = DISPLAY_NAME_LENGTH, message = "{errors.maxlength}" + DISPLAY_NAME_LENGTH)
	private String displayName;

	@Column(length = NAME_LENGTH, nullable = false)
	public String getName() {
		return name;
	}

	public void setName(String name) {
		this.name = name;
	}

	@Column(length = DISPLAY_NAME_LENGTH, nullable = false)
	public String getDisplayName() {
		return displayName;
	}

	public void setDisplayName(String displayName) {
		this.displayName = displayName;
	}

	@OneToMany(mappedBy = "role")
	@JsonIgnore
	public List<UserRoleMap> getUserRoleMaps() {
		return userRoleMaps;
	}

	public void setUserRoleMaps(List<UserRoleMap> userRoleMaps) {
		this.userRoleMaps = userRoleMaps;
	}
	
	@Column
	public Boolean getCanGenerateReports() {
		return canGenerateReports != null && canGenerateReports;
	}

	public void setCanGenerateReports(Boolean canGenerateReports) {
		this.canGenerateReports = canGenerateReports;
	}

	@Column
	public Boolean getCanGenerateWafRules() {
		return canGenerateWafRules != null && canGenerateWafRules;
	}

	public void setCanGenerateWafRules(Boolean canGenerateWafRules) {
		this.canGenerateWafRules = canGenerateWafRules;
	}

	@Column
	public Boolean getCanManageApiKeys() {
		return canManageApiKeys != null && canManageApiKeys;
	}

	public void setCanManageApiKeys(Boolean canManageApiKeys) {
		this.canManageApiKeys = canManageApiKeys;
	}

	@Column
	public Boolean getCanManageApplications() {
		return canManageApplications != null && canManageApplications;
	}

	public void setCanManageApplications(Boolean canManageApplications) {
		this.canManageApplications = canManageApplications;
	}

	@Column
	public Boolean getCanManageGroups() {
		return canManageGroups != null && canManageGroups;
	}

	public void setCanManageGroups(Boolean canManageGroups) {
		this.canManageGroups = canManageGroups;
	}

	@Column
	public Boolean getCanManageRemoteProviders() {
		return canManageRemoteProviders != null && canManageRemoteProviders;
	}

	public void setCanManageRemoteProviders(Boolean canManageRemoteProviders) {
		this.canManageRemoteProviders = canManageRemoteProviders;
	}

	@Column
	public Boolean getCanManageRoles() {
		return canManageRoles != null && canManageRoles;
	}

	public void setCanManageRoles(Boolean canManageRoles) {
		this.canManageRoles = canManageRoles;
	}

	@Column
	public Boolean getCanManageTeams() {
		return canManageTeams != null && canManageTeams;
	}

	public void setCanManageTeams(Boolean canManageTeams) {
		this.canManageTeams = canManageTeams;
	}

	@Column
	public Boolean getCanManageUsers() {
		return canManageUsers != null && canManageUsers;
	}

	public void setCanManageUsers(Boolean canManageUsers) {
		this.canManageUsers = canManageUsers;
	}

	@Column
	public Boolean getCanManageWafs() {
		return canManageWafs != null && canManageWafs;
	}

	public void setCanManageWafs(Boolean canManageWafs) {
		this.canManageWafs = canManageWafs;
	}

	@Column
	public Boolean getCanModifyVulnerabilities() {
		return canModifyVulnerabilities != null && canModifyVulnerabilities;
	}

	public void setCanModifyVulnerabilities(Boolean canModifyVulnerabilities) {
		this.canModifyVulnerabilities = canModifyVulnerabilities;
	}

	@Column
	public Boolean getCanSubmitDefects() {
		return canSubmitDefects != null && canSubmitDefects;
	}

	public void setCanSubmitDefects(Boolean canSubmitDefects) {
		this.canSubmitDefects = canSubmitDefects;
	}

	@Column
	public Boolean getCanUploadScans() {
		return canUploadScans != null && canUploadScans;
	}

	public void setCanUploadScans(Boolean canUploadScans) {
		this.canUploadScans = canUploadScans;
	}

	@Column
	public Boolean getCanViewErrorLogs() {
		return canViewErrorLogs != null && canViewErrorLogs;
	}

	public void setCanViewErrorLogs(Boolean canViewErrorLogs) {
		this.canViewErrorLogs = canViewErrorLogs;
	}

	@Column
	public Boolean getCanViewJobStatuses() {
		return canViewJobStatuses != null && canViewJobStatuses;
	}

	public void setCanViewJobStatuses(Boolean canViewJobStatuses) {
		this.canViewJobStatuses = canViewJobStatuses;
	}
}
