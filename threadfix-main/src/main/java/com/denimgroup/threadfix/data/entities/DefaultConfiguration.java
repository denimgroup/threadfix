package com.denimgroup.threadfix.data.entities;

import java.util.Calendar;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.Table;

@Entity
@Table(name="DefaultConfiguration")
public class DefaultConfiguration extends BaseEntity {
	
	private static final long serialVersionUID = 2584623185996706729L;
	
	private Boolean globalGroupEnabled = null;
	private Integer defaultRoleId = null;
	
	private String activeDirectoryBase, activeDirectoryURL, activeDirectoryUsername, activeDirectoryCredentials;
	
	private Calendar lastScannerMappingsUpdate;
	
	@Column
	public Integer getDefaultRoleId() {
		return defaultRoleId;
	}
	
	public void setDefaultRoleId(Integer defaultRoleId) {
		this.defaultRoleId = defaultRoleId;
	}
	
	@Column
	public Boolean getGlobalGroupEnabled() {
		return globalGroupEnabled != null && globalGroupEnabled;
	}
	public void setGlobalGroupEnabled(Boolean globalGroupEnabled) {
		this.globalGroupEnabled = globalGroupEnabled;
	}
	
	@Column(length=256)
	public void setActiveDirectoryBase(String activeDirectoryBase) {
		this.activeDirectoryBase = activeDirectoryBase;
	}
	
	public String getActiveDirectoryURL() {
		if (activeDirectoryURL == null) {
			return "";
		} else {
			return activeDirectoryURL;
		}
	}
	
	@Column(length=256)
	public void setActiveDirectoryURL(String activeDirectoryURL) {
		this.activeDirectoryURL = activeDirectoryURL;
	}
	public String getActiveDirectoryUsername() {
		if (activeDirectoryUsername == null) {
			return "";
		} else {
			return activeDirectoryUsername;
		}
	}
	
	@Column(length=256)
	public void setActiveDirectoryUsername(String activeDirectoryUsername) {
		this.activeDirectoryUsername = activeDirectoryUsername;
	}
	
	public String getActiveDirectoryCredentials() {
		if (activeDirectoryCredentials == null) {
			return "";
		} else {
			return activeDirectoryCredentials;
		}
	}
	
	@Column(length=256)
	public void setActiveDirectoryCredentials(String activeDirectoryCredentials) {
		this.activeDirectoryCredentials = activeDirectoryCredentials;
	}
	
	public String getActiveDirectoryBase() {
		if (activeDirectoryCredentials == null) {
			return "";
		} else {
			return activeDirectoryBase;
		}
	}

	@Column
	public Calendar getLastScannerMappingsUpdate() {
		return lastScannerMappingsUpdate;
	}

	public void setLastScannerMappingsUpdate(Calendar lastScannerMappingsUpdate) {
		this.lastScannerMappingsUpdate = lastScannerMappingsUpdate;
	}
	
}
