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
package com.denimgroup.threadfix.data.entities;

import com.denimgroup.threadfix.views.AllViews;
import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonView;
import org.hibernate.validator.constraints.NotEmpty;

import javax.persistence.*;
import javax.validation.constraints.Size;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

@Entity
@Table(name = "Role")
public class Role extends AuditableEntity {
	
	public static final String USER = "ROLE_USER";
	
	public static final int NAME_LENGTH = 25;
	public static final int DISPLAY_NAME_LENGTH = 25;

    private List<User> users;
    private List<Group> groups;

	private static final long serialVersionUID = -1609499610449048270L;
	
	private Boolean canGenerateReports, canGenerateWafRules, canManageApiKeys,
			canManageApplications, canManageDefectTrackers, canManageGrcTools,
			canManageRemoteProviders, canManageRoles, canManageTeams,
			canManageUsers, canManageWafs, canManageVulnFilters, canModifyVulnerabilities,
			canSubmitDefects, canUploadScans, canViewErrorLogs, canManageScanAgents, canManageSystemSettings,
            canViewJobStatuses, enterprise, canManageTags, canSubmitComments, canManageScanResultFilters,
            canManageCustomCweText, canManageEmailReports, canManageGroups, canManagePolicies;

    public static final String[] PROTECTED_PERMISSIONS = {
            "canManageRoles", "canManageUsers"
    };

    public static final String[] ALL_PERMISSIONS;

    // this prevents us from needing to update this string array every time
    static {
        Permission[] permissionValues = Permission.values();
        String[] permissions = new String[permissionValues.length];
        for (int i = 0; i < permissionValues.length; i++) {
            permissions[i] = permissionValues[i].getCamelCase();
        }

        ALL_PERMISSIONS = permissions;
    }

    @NotEmpty(message = "{errors.required}")
    @Size(max = DISPLAY_NAME_LENGTH, message = "{errors.maxlength}" + DISPLAY_NAME_LENGTH)
    private String displayName;

    @Column
    @JsonView(AllViews.TableRow.class)
    public Boolean getCanManageSystemSettings() {
        return canManageSystemSettings != null && canManageSystemSettings;
    }

    public void setCanManageSystemSettings(Boolean canManageSystemSettings) {
        this.canManageSystemSettings = canManageSystemSettings;
    }

    @JsonView(Object.class)
    @Column(length = DISPLAY_NAME_LENGTH, nullable = false)
    public String getDisplayName() {
        return displayName;
    }

    public void setDisplayName(String displayName) {
        this.displayName = displayName;
    }

    @Column
    @JsonView(AllViews.TableRow.class)
    public Boolean getCanManageScanAgents() {
        return canManageScanAgents != null && canManageScanAgents;
    }

    public void setCanManageScanAgents(Boolean canManageScanAgents) {
        this.canManageScanAgents = canManageScanAgents;
    }

    @Column
    @JsonView(AllViews.TableRow.class)
    public Boolean getCanGenerateReports() {
        return canGenerateReports != null && canGenerateReports;
    }

    public void setCanGenerateReports(Boolean canGenerateReports) {
        this.canGenerateReports = canGenerateReports;
    }

    @Column
    @JsonView(AllViews.TableRow.class)
    public Boolean getCanGenerateWafRules() {
        return canGenerateWafRules != null && canGenerateWafRules;
    }

    public void setCanGenerateWafRules(Boolean canGenerateWafRules) {
        this.canGenerateWafRules = canGenerateWafRules;
    }

    @Column
    @JsonView(AllViews.TableRow.class)
    public Boolean getCanManageApiKeys() {
        return canManageApiKeys != null && canManageApiKeys;
    }

    public void setCanManageApiKeys(Boolean canManageApiKeys) {
        this.canManageApiKeys = canManageApiKeys;
    }

    @Column
    @JsonView(AllViews.TableRow.class)
    public Boolean getCanManageApplications() {
        return canManageApplications != null && canManageApplications;
    }

    public void setCanManageApplications(Boolean canManageApplications) {
        this.canManageApplications = canManageApplications;
    }

    @Column
    @JsonView(AllViews.TableRow.class)
    public Boolean getCanManageGrcTools() {
        return canManageGrcTools != null && canManageGrcTools;
    }

    public void setCanManageGrcTools(Boolean canManageGrcTools) {
        this.canManageGrcTools = canManageGrcTools;
    }

    @Column
    @JsonView(AllViews.TableRow.class)
    public Boolean getCanManageDefectTrackers() {
        return canManageDefectTrackers != null && canManageDefectTrackers;
    }

    public void setCanManageDefectTrackers(Boolean canManageDefectTrackers) {
        this.canManageDefectTrackers = canManageDefectTrackers;
    }

    @Column
    @JsonView(AllViews.TableRow.class)
    public Boolean getCanManageRemoteProviders() {
        return canManageRemoteProviders != null && canManageRemoteProviders;
    }

    public void setCanManageRemoteProviders(Boolean canManageRemoteProviders) {
        this.canManageRemoteProviders = canManageRemoteProviders;
    }

    @Column
    @JsonView(AllViews.TableRow.class)
    public Boolean getCanManageRoles() {
        return canManageRoles != null && canManageRoles;
    }

    public void setCanManageRoles(Boolean canManageRoles) {
        this.canManageRoles = canManageRoles;
    }

    @Column
    @JsonView(AllViews.TableRow.class)
    public Boolean getCanManageTeams() {
        return canManageTeams != null && canManageTeams;
    }

    public void setCanManageTeams(Boolean canManageTeams) {
        this.canManageTeams = canManageTeams;
    }

    @Column
    @JsonView(AllViews.TableRow.class)
    public Boolean getCanManageUsers() {
        return canManageUsers != null && canManageUsers;
    }

    public void setCanManageUsers(Boolean canManageUsers) {
        this.canManageUsers = canManageUsers;
    }

    @Column
    @JsonView(AllViews.TableRow.class)
    public Boolean getCanManageWafs() {
        return canManageWafs != null && canManageWafs;
    }

    public void setCanManageWafs(Boolean canManageWafs) {
        this.canManageWafs = canManageWafs;
    }

    @Column
    @JsonView(AllViews.TableRow.class)
    public Boolean getCanModifyVulnerabilities() {
		return canModifyVulnerabilities != null && canModifyVulnerabilities;
	}

	public void setCanModifyVulnerabilities(Boolean canModifyVulnerabilities) {
		this.canModifyVulnerabilities = canModifyVulnerabilities;
	}

	@Column
    @JsonView(AllViews.TableRow.class)
    public Boolean getCanManageVulnFilters() {
		return canManageVulnFilters != null && canManageVulnFilters;
	}

	public void setCanManageVulnFilters(Boolean canManageVulnFilters) {
		this.canManageVulnFilters = canManageVulnFilters;
	}

	@Column
    @JsonView(AllViews.TableRow.class)
	public Boolean getCanSubmitDefects() {
		return canSubmitDefects != null && canSubmitDefects;
	}

	public void setCanSubmitDefects(Boolean canSubmitDefects) {
		this.canSubmitDefects = canSubmitDefects;
	}

	@Column
    @JsonView(AllViews.TableRow.class)
	public Boolean getCanUploadScans() {
		return canUploadScans != null && canUploadScans;
	}

	public void setCanUploadScans(Boolean canUploadScans) {
		this.canUploadScans = canUploadScans;
	}

	@Column
    @JsonView(AllViews.TableRow.class)
	public Boolean getCanViewErrorLogs() {
		return canViewErrorLogs != null && canViewErrorLogs;
	}

	public void setCanViewErrorLogs(Boolean canViewErrorLogs) {
		this.canViewErrorLogs = canViewErrorLogs;
	}

	@Column
    @JsonView(AllViews.TableRow.class)
	public Boolean getCanViewJobStatuses() {
		return canViewJobStatuses != null && canViewJobStatuses;
	}

	public void setCanViewJobStatuses(Boolean canViewJobStatuses) {
		this.canViewJobStatuses = canViewJobStatuses;
	}
	
	@Column
    @JsonView(AllViews.TableRow.class)
	public Boolean getEnterprise(){
		return enterprise != null && enterprise;
	}
	
	public void setEnterprise(Boolean enterprise){
		this.enterprise = enterprise;
	}

    @Column
    @JsonView(AllViews.TableRow.class)
    public Boolean getCanManageTags() {
        return canManageTags != null && canManageTags;
    }

    public void setCanManageTags(Boolean canManageTags) {
        this.canManageTags = canManageTags;
    }

    @Column
    @JsonView(AllViews.TableRow.class)
    public Boolean getCanSubmitComments() {
        return canSubmitComments != null && canSubmitComments;
    }

    public void setCanSubmitComments(Boolean canSubmitComments) {
        this.canSubmitComments = canSubmitComments;
    }

    @Column
    @JsonView(AllViews.TableRow.class)
    public Boolean getCanManageScanResultFilters(){
        return canManageScanResultFilters != null && canManageScanResultFilters;
    }

    public void setCanManageScanResultFilters(Boolean canManageScanResultFilters) {
        this.canManageScanResultFilters = canManageScanResultFilters;
    }

    @Column
    @JsonView(AllViews.TableRow.class)
    public Boolean getCanManageCustomCweText() { return canManageCustomCweText != null && canManageCustomCweText; }

    public void setCanManageCustomCweText(Boolean canManageCustomCweText) {
        this.canManageCustomCweText = canManageCustomCweText;
    }

    @Column
    @JsonView(AllViews.TableRow.class)
    public Boolean getCanManageEmailReports() {
        return canManageEmailReports != null && canManageEmailReports;
    }

    public void setCanManageEmailReports(Boolean canManageEmailReports) {
        this.canManageEmailReports = canManageEmailReports;
    }

    @Column
    @JsonView(AllViews.TableRow.class)
    public Boolean getCanManageGroups() {
        return canManageGroups != null && canManageGroups;
    }

    public void setCanManageGroups(Boolean canManageGroups) {
        this.canManageGroups = canManageGroups;
    }

    @Column
    @JsonView(AllViews.TableRow.class)
    public Boolean getCanManagePolicies() {
        return canManagePolicies != null && canManagePolicies;
    }

    public void setCanManagePolicies(Boolean canManagePolicies) {
        this.canManagePolicies = canManagePolicies;
    }

    @Transient
	public Set<Permission> getPermissions() {
		Set<Permission> permissions = new HashSet<Permission>();
	
		if (getCanGenerateReports())
			permissions.add(Permission.CAN_GENERATE_REPORTS);

		if (getCanGenerateWafRules())
			permissions.add(Permission.CAN_GENERATE_WAF_RULES);

		if (getCanManageScanAgents())
			permissions.add(Permission.CAN_MANAGE_SCAN_AGENTS);

		if (getCanManageApiKeys())
			permissions.add(Permission.CAN_MANAGE_API_KEYS);

		if (getCanManageApplications())
			permissions.add(Permission.CAN_MANAGE_APPLICATIONS);

		if (getCanManageDefectTrackers())
			permissions.add(Permission.CAN_MANAGE_DEFECT_TRACKERS);

		if (getCanManageGrcTools())
			permissions.add(Permission.CAN_MANAGE_GRC_TOOLS);

		if (getCanManageRemoteProviders())
			permissions.add(Permission.CAN_MANAGE_REMOTE_PROVIDERS);

		if (getCanManageRoles())
			permissions.add(Permission.CAN_MANAGE_ROLES);

		if (getCanManageTeams())
			permissions.add(Permission.CAN_MANAGE_TEAMS);

		if (getCanManageUsers())
			permissions.add(Permission.CAN_MANAGE_USERS);

		if (getCanManageSystemSettings())
			permissions.add(Permission.CAN_MANAGE_SYSTEM_SETTINGS);

		if (getCanManageWafs())
			permissions.add(Permission.CAN_MANAGE_WAFS);

		if (getCanModifyVulnerabilities())
			permissions.add(Permission.CAN_MODIFY_VULNERABILITIES);

		if (getCanManageVulnFilters())
			permissions.add(Permission.CAN_MANAGE_VULN_FILTERS);

		if (getCanSubmitDefects())
			permissions.add(Permission.CAN_SUBMIT_DEFECTS);

		if (getCanUploadScans())
			permissions.add(Permission.CAN_UPLOAD_SCANS);

		if (getCanViewErrorLogs())
			permissions.add(Permission.CAN_VIEW_ERROR_LOGS);

		if (getEnterprise())
			permissions.add(Permission.ENTERPRISE);

        if (getCanManageTags() != null && getCanManageTags())
            permissions.add(Permission.CAN_MANAGE_TAGS);

        if (getCanSubmitComments() != null && getCanSubmitComments())
            permissions.add(Permission.CAN_SUBMIT_COMMENTS);

        if (getCanManageGroups() != null && getCanManageGroups())
            permissions.add(Permission.CAN_MANAGE_GROUPS);

        if (getCanManageScanResultFilters() != null && getCanManageScanResultFilters())
            permissions.add(Permission.CAN_MANAGE_SCAN_RESULT_FILTERS);

        if (getCanManageCustomCweText() != null && getCanManageCustomCweText())
            permissions.add(Permission.CAN_MANAGE_CUSTOM_CWE_TEXT);

        if (getCanManageEmailReports() != null && getCanManageEmailReports())
            permissions.add(Permission.CAN_MANAGE_EMAIL_REPORTS);

        if (getCanManagePolicies() != null && getCanManagePolicies())
            permissions.add(Permission.CAN_MANAGE_POLICIES);

		return permissions;
	}
	
	boolean canDelete = false;
	
	@Transient
    @JsonView(AllViews.TableRow.class)
	public boolean isCanDelete() {
		return canDelete;
	}

	public void setCanDelete(boolean canDelete) {
		this.canDelete = canDelete;
	}

    @OneToMany(mappedBy = "globalRole")
    @JsonIgnore
    public List<User> getUsers() {
        return users;
    }

    public void setUsers(List<User> users) {
        this.users = users;
    }

    @OneToMany(mappedBy = "globalRole")
    @JsonIgnore
    public List<Group> getGroups() {
        return groups;
    }

    public void setGroups(List<Group> groups) {
        this.groups = groups;
    }


    public void unNullPermissions() {
        boolean newPermissionStatus = getCanManageRoles();

        if (canGenerateReports == null)
            setCanGenerateReports(newPermissionStatus);

        if (canGenerateWafRules == null)
            setCanGenerateWafRules(newPermissionStatus);

        if (canManageScanAgents == null)
            setCanManageScanAgents(newPermissionStatus);

        if (canManageApiKeys == null)
            setCanManageApiKeys(newPermissionStatus);

        if (canManageApplications == null)
            setCanManageApplications(newPermissionStatus);

        if (canManageDefectTrackers == null)
            setCanManageDefectTrackers(newPermissionStatus);

        if (canManageGrcTools == null)
            setCanManageGrcTools(newPermissionStatus);

        if (canManageRemoteProviders == null)
            setCanManageRemoteProviders(newPermissionStatus);

        if (canManageRoles == null)
            setCanManageRoles(newPermissionStatus);

        if (canManageTeams == null)
            setCanManageTeams(newPermissionStatus);

        if (canManageUsers == null)
            setCanManageUsers(newPermissionStatus);

        if (canManageSystemSettings == null)
            setCanManageSystemSettings(newPermissionStatus);

        if (canManageWafs == null)
            setCanManageWafs(newPermissionStatus);

        if (canModifyVulnerabilities == null)
            setCanModifyVulnerabilities(newPermissionStatus);

        if (canManageVulnFilters == null)
            setCanManageVulnFilters(newPermissionStatus);

        if (canSubmitDefects == null)
            setCanSubmitDefects(newPermissionStatus);

        if (canUploadScans == null)
            setCanUploadScans(newPermissionStatus);

        if (canViewErrorLogs == null)
            setCanViewErrorLogs(newPermissionStatus);

        if (canManageTags == null)
            setCanManageTags(newPermissionStatus);

        if (canSubmitComments == null)
            setCanSubmitComments(newPermissionStatus);

        if (canManageGroups == null)
            setCanManageGroups(newPermissionStatus);

        if (canManageScanResultFilters == null)
            setCanManageScanResultFilters(newPermissionStatus);

        if (canManageCustomCweText == null)
            setCanManageCustomCweText(newPermissionStatus);

        if (canManageEmailReports == null)
            setCanManageEmailReports(newPermissionStatus);

        if (canManagePolicies == null)
            setCanManagePolicies(newPermissionStatus);
    }

    @Override
    public String toString() {
        return displayName == null ? "Unnamed Role." : displayName + " (Role)";
    }
}

