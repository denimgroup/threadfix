////////////////////////////////////////////////////////////////////////
//
//     Copyright (c) 2009-2014 Denim Group, Ltd.
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

public enum Permission {
	CAN_GENERATE_REPORTS("ROLE_CAN_GENERATE_REPORTS","canGenerateReports"),
	CAN_GENERATE_WAF_RULES("ROLE_CAN_GENERATE_WAF_RULES","canGenerateWafRules"),
	CAN_MANAGE_API_KEYS("ROLE_CAN_MANAGE_API_KEYS","canManageApiKeys"),
	CAN_MANAGE_APPLICATIONS("ROLE_CAN_MANAGE_APPLICATIONS","canManageApplications"),
	CAN_MANAGE_GRC_TOOLS("ROLE_CAN_MANAGE_GRC_TOOLS","canManageGrcTools"),
	CAN_MANAGE_DEFECT_TRACKERS("ROLE_CAN_MANAGE_DEFECT_TRACKERS","canManageDefectTrackers"),
	CAN_MANAGE_REMOTE_PROVIDERS("ROLE_CAN_MANAGE_REMOTE_PROVIDERS","canManageRemoteProviders"),
	CAN_MANAGE_ROLES("ROLE_CAN_MANAGE_ROLES","canManageRoles"),
	CAN_MANAGE_TEAMS("ROLE_CAN_MANAGE_TEAMS","canManageTeams"),
	CAN_MANAGE_USERS("ROLE_CAN_MANAGE_USERS","canManageUsers"),
	CAN_MANAGE_WAFS("ROLE_CAN_MANAGE_WAFS","canManageWafs"),
    CAN_MANAGE_VULN_FILTERS("ROLE_CAN_MANAGE_VULN_FILTERS","canManageVulnFilters"),
	CAN_MODIFY_VULNERABILITIES("ROLE_CAN_MODIFY_VULNERABILITIES","canModifyVulnerabilities"),
	CAN_SUBMIT_DEFECTS("ROLE_CAN_SUBMIT_DEFECTS","canSubmitDefects"),
	CAN_UPLOAD_SCANS("ROLE_CAN_UPLOAD_SCANS","canUploadScans"),
	CAN_MANAGE_SCAN_AGENTS("ROLE_CAN_MANAGE_SCAN_AGENTS","canManageScanAgents"),
	CAN_MANAGE_SYSTEM_SETTINGS("ROLE_CAN_MANAGE_SYSTEM_SETTINGS","canManageSystemSettings"),
	CAN_VIEW_ERROR_LOGS("ROLE_CAN_VIEW_ERROR_LOGS","canViewErrorLogs"),
//	CAN_VIEW_JOB_STATUSES("ROLE_CAN_VIEW_JOB_STATUSES","canViewJobStatuses"),
	ENTERPRISE("ROLE_ENTERPRISE","enterprise"),
	READ_ACCESS("ROLE_READ_ACCESS","readAccess"),
    CAN_MANAGE_TAGS("ROLE_CAN_MANAGE_TAGS","canManageTags");

	private String text, camelCase;
	
	public String getText() { 
		return this.text; 
	}
	
	public String getCamelCase() {
		return this.camelCase;
	}

	Permission(String text, String camelCase) { 
		this.text = text;
		this.camelCase = camelCase;
	}

}
