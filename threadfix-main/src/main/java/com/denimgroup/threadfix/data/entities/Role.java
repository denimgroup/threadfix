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
package com.denimgroup.threadfix.data.entities;

import java.util.HashSet;
import java.util.Set;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.Table;
import javax.persistence.Transient;
import javax.validation.constraints.Size;

import org.hibernate.validator.constraints.NotEmpty;

@Entity
@Table(name = "Role")
public class Role extends AuditableEntity {
	
	public static final String USER = "ROLE_USER";
	
	public static final int NAME_LENGTH = 25;
	public static final int DISPLAY_NAME_LENGTH = 25;

	private static final long serialVersionUID = -1609499610449048270L;
	
	private Boolean canGenerateReports, canGenerateWafRules, canManageApiKeys,
			canManageApplications, canManageDefectTrackers,
			canManageRemoteProviders, canManageRoles, canManageTeams,
			canManageUsers, canManageWafs, canModifyVulnerabilities,
			canSubmitDefects, canUploadScans, canViewErrorLogs,
			canViewJobStatuses,enterprise;
	
	public static final String[] PROTECTED_PERMISSIONS = new String[]{
			"canManageRoles", "canManageUsers"
	};
	
	public static final String[] ALL_PERMISSIONS = new String[] {
		"canManageUsers", "canManageRoles", "canManageTeams", "canManageDefectTrackers",
		"canModifyVulnerabilities", "canUploadScans", "canViewErrorLogs", "canSubmitDefects",
		"canManageWafs", "canGenerateWafRules", "canManageApiKeys", "canManageRemoteProviders",
		"canGenerateReports", "canViewJobStatuses", "canManageApplications", "enterprise"
	};
	
	@NotEmpty(message = "{errors.required}")
	@Size(max = DISPLAY_NAME_LENGTH, message = "{errors.maxlength}" + DISPLAY_NAME_LENGTH)
	private String displayName;

	@Column(length = DISPLAY_NAME_LENGTH, nullable = false)
	public String getDisplayName() {
		return displayName;
	}

	public void setDisplayName(String displayName) {
		this.displayName = displayName;
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
	public Boolean getCanManageDefectTrackers() {
		return canManageDefectTrackers != null && canManageDefectTrackers;
	}

	public void setCanManageDefectTrackers(Boolean canManageDefectTrackers) {
		this.canManageDefectTrackers = canManageDefectTrackers;
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
	
	@Column
	public Boolean getEnterprise(){
		return enterprise != null && enterprise;
	}
	
	public void setEnterprise(Boolean enterprise){
		this.enterprise = enterprise;
	}

	@Transient
	public Set<Permission> getPermissions() {
		Set<Permission> permissions = new HashSet<>();
	
		if (getCanGenerateReports())
			permissions.add(Permission.CAN_GENERATE_REPORTS);

		if (getCanGenerateWafRules())
			permissions.add(Permission.CAN_GENERATE_WAF_RULES);

		if (getCanManageApiKeys())
			permissions.add(Permission.CAN_MANAGE_API_KEYS);

		if (getCanManageApplications())
			permissions.add(Permission.CAN_MANAGE_APPLICATIONS);

		if (getCanManageDefectTrackers())
			permissions.add(Permission.CAN_MANAGE_DEFECT_TRACKERS);

		if (getCanManageRemoteProviders())
			permissions.add(Permission.CAN_MANAGE_REMOTE_PROVIDERS);

		if (getCanManageRoles())
			permissions.add(Permission.CAN_MANAGE_ROLES);

		if (getCanManageTeams())
			permissions.add(Permission.CAN_MANAGE_TEAMS);

		if (getCanManageUsers())
			permissions.add(Permission.CAN_MANAGE_USERS);

		if (getCanManageWafs())
			permissions.add(Permission.CAN_MANAGE_WAFS);

		if (getCanModifyVulnerabilities())
			permissions.add(Permission.CAN_MODIFY_VULNERABILITIES);

		if (getCanSubmitDefects())
			permissions.add(Permission.CAN_SUBMIT_DEFECTS);

		if (getCanUploadScans())
			permissions.add(Permission.CAN_UPLOAD_SCANS);

		if (getCanViewErrorLogs())
			permissions.add(Permission.CAN_VIEW_ERROR_LOGS);

		if (getCanViewJobStatuses())
			permissions.add(Permission.CAN_VIEW_JOB_STATUSES);
		
		if (getEnterprise())
			permissions.add(Permission.ENTERPRISE);

		return permissions;
	}
	
	boolean canDelete = false;
	
	@Transient
	public boolean isCanDelete() {
		return canDelete;
	}

	public void setCanDelete(boolean canDelete) {
		this.canDelete = canDelete;
	}
}

