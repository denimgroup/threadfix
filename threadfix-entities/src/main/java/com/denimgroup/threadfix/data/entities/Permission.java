package com.denimgroup.threadfix.data.entities;

public enum Permission {
	CAN_GENERATE_REPORTS("ROLE_CAN_GENERATE_REPORTS","canGenerateReports"),
	CAN_GENERATE_WAF_RULES("ROLE_CAN_GENERATE_WAF_RULES","canGenerateWafRules"),
	CAN_MANAGE_API_KEYS("ROLE_CAN_MANAGE_API_KEYS","canManageApiKeys"),
	CAN_MANAGE_APPLICATIONS("ROLE_CAN_MANAGE_APPLICATIONS","canManageApplications"),
	CAN_MANAGE_DEFECT_TRACKERS("ROLE_CAN_MANAGE_DEFECT_TRACKERS","canManageDefectTrackers"),
	CAN_MANAGE_REMOTE_PROVIDERS("ROLE_CAN_MANAGE_REMOTE_PROVIDERS","canManageRemoteProviders"),
	CAN_MANAGE_ROLES("ROLE_CAN_MANAGE_ROLES","canManageRoles"),
	CAN_MANAGE_TEAMS("ROLE_CAN_MANAGE_TEAMS","canManageTeams"),
	CAN_MANAGE_USERS("ROLE_CAN_MANAGE_USERS","canManageUsers"),
	CAN_MANAGE_WAFS("ROLE_CAN_MANAGE_WAFS","canManageWafs"),
	CAN_MODIFY_VULNERABILITIES("ROLE_CAN_MODIFY_VULNERABILITIES","canModifyVulnerabilities"),
	CAN_SUBMIT_DEFECTS("ROLE_CAN_SUBMIT_DEFECTS","canSubmitDefects"),
	CAN_UPLOAD_SCANS("ROLE_CAN_UPLOAD_SCANS","canUploadScans"),
	CAN_VIEW_ERROR_LOGS("ROLE_CAN_VIEW_ERROR_LOGS","canViewErrorLogs"),
	CAN_VIEW_JOB_STATUSES("ROLE_CAN_VIEW_JOB_STATUSES","canViewJobStatuses"),
	ENTERPRISE("ROLE_ENTERPRISE","enterprise"),
	READ_ACCESS("ROLE_READ_ACCESS","readAccess");

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
