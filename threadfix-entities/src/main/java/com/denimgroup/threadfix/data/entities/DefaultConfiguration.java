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

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.Table;
import javax.persistence.Transient;
import java.util.Calendar;
import java.util.HashMap;
import java.util.Map;

@Entity
@Table(name="DefaultConfiguration")
public class DefaultConfiguration extends BaseEntity {
	
	private static final long serialVersionUID = 2584623185996706729L;
	
	private Boolean globalGroupEnabled = null;
    private Boolean hasAddedScheduledImports = null;
    private Boolean hasAddedScheduledDefectTrackerUpdates = null;
    private Integer defaultRoleId = null;

    private Boolean hasCachedData = null;

	private String activeDirectoryBase, activeDirectoryURL, activeDirectoryUsername, activeDirectoryCredentials;

    private String proxyHost = null, proxyUsername = null, proxyPassword = null, proxyUsernameEncrypted = null, proxyPasswordEncrypted = null;
    private Integer proxyPort = null;

    private Calendar lastScannerMappingsUpdate;

    private Integer sessionTimeout = null;

    public static DefaultConfiguration getInitialConfig() {
        DefaultConfiguration config = new DefaultConfiguration();
        config.setDefaultRoleId(1);
        config.setGlobalGroupEnabled(true);
        config.setHasAddedScheduledImports(false);
        config.setHasAddedScheduledDefectTrackerUpdates(false);
        return config;
    }

    @Column
    public Integer getSessionTimeout() {
        return sessionTimeout;
    }

    public void setSessionTimeout(Integer sessionTimeout) {
        this.sessionTimeout = sessionTimeout;
    }


    @Column
    public Boolean getHasAddedScheduledImports() {
        return hasAddedScheduledImports != null && hasAddedScheduledImports;
    }

    public void setHasAddedScheduledImports(Boolean hasAddedScheduledImports) {
        this.hasAddedScheduledImports = hasAddedScheduledImports;
    }

    @Column
    public Boolean getHasAddedScheduledDefectTrackerUpdates() {
        return hasAddedScheduledDefectTrackerUpdates != null && hasAddedScheduledDefectTrackerUpdates;
    }

    public void setHasAddedScheduledDefectTrackerUpdates(Boolean hasAddedScheduledDefectTrackerUpdates) {
        this.hasAddedScheduledDefectTrackerUpdates = hasAddedScheduledDefectTrackerUpdates;
    }

    @Column
    public Boolean getHasCachedData() {
        return hasCachedData != null && hasCachedData;
    }

    public void setHasCachedData(Boolean hasCachedData) {
        this.hasCachedData = hasCachedData;
    }

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
        return activeDirectoryURL == null ? "" : activeDirectoryURL;
	}
	
	@Column(length=256)
	public void setActiveDirectoryURL(String activeDirectoryURL) {
		this.activeDirectoryURL = activeDirectoryURL;
	}
	public String getActiveDirectoryUsername() {
		return activeDirectoryUsername == null ? "" : activeDirectoryUsername;
	}
	
	@Column(length=256)
	public void setActiveDirectoryUsername(String activeDirectoryUsername) {
		this.activeDirectoryUsername = activeDirectoryUsername;
	}
	
	public String getActiveDirectoryCredentials() {
		return activeDirectoryCredentials == null ? "" : activeDirectoryCredentials;
	}
	
	@Column(length=256)
	public void setActiveDirectoryCredentials(String activeDirectoryCredentials) {
		this.activeDirectoryCredentials = activeDirectoryCredentials;
	}
	
	public String getActiveDirectoryBase() {
		return activeDirectoryCredentials == null ? "" : activeDirectoryBase;
	}

	@Column
	public Calendar getLastScannerMappingsUpdate() {
		return lastScannerMappingsUpdate;
	}

	public void setLastScannerMappingsUpdate(Calendar lastScannerMappingsUpdate) {
		this.lastScannerMappingsUpdate = lastScannerMappingsUpdate;
	}

    @Transient
    public String getProxyUsername() {
        return proxyUsername;
    }

    public void setProxyUsername(String proxyUsername) {
        this.proxyUsername = proxyUsername;
    }

    @Transient
    public String getProxyPassword() {
        return proxyPassword;
    }

    public void setProxyPassword(String proxyPassword) {
        this.proxyPassword = proxyPassword;
    }

    @Column
    public Integer getProxyPort() {
        return proxyPort;
    }

    public void setProxyPort(Integer proxyPort) {
        this.proxyPort = proxyPort;
    }

    @Column(length = 1024)
    public String getProxyUsernameEncrypted() {
        return proxyUsernameEncrypted;
    }

    public void setProxyUsernameEncrypted(String proxyUsernameEncrypted) {
        this.proxyUsernameEncrypted = proxyUsernameEncrypted;
    }

    @Column(length = 1024)
    public String getProxyPasswordEncrypted() {
        return proxyPasswordEncrypted;
    }

    public void setProxyPasswordEncrypted(String proxyPasswordEncrypted) {
        this.proxyPasswordEncrypted = proxyPasswordEncrypted;
    }

    @Column(length = 1024)
    public String getProxyHost() {
        return proxyHost;
    }

    public void setProxyHost(String proxyHost) {
        this.proxyHost = proxyHost;
    }

    @Transient
    public boolean hasConfiguredHostAndPort() {
        return proxyHost != null && !proxyHost.equals("") &&
                proxyPort != null && proxyPort > 0;
    }

    @Transient
    public boolean hasConfiguredCredentials() {
        return shouldUseProxyCredentials && proxyUsername != null && !proxyUsername.equals("") &&
                proxyPassword != null && !proxyPassword.equals("");
    }

    @Transient
    public <T> boolean shouldUseProxy(Class<T> classToProxy) {
        Boolean aBoolean = getProxySupportMap().get(classToProxy.getSimpleName());
        return aBoolean != null && aBoolean;
    }

    @Transient
    private Map<String, Boolean> getProxySupportMap() {
        Map<String, Boolean> map = new HashMap<String, Boolean>();
        map.put("BugzillaDefectTracker", getShouldProxyBugzilla());
        map.put("JiraDefectTracker", getShouldProxyJira());
        map.put("TFSDefectTracker", getShouldProxyTFS());
        map.put("VersionOneDefectTracker", getShouldProxyVersionOne());
        map.put("HPQualityCenterDefectTracker", getShouldProxyHPQC());
        map.put("WhiteHatRemoteProvider", getShouldProxyWhiteHat());
        map.put("VeracodeRemoteProvider", getShouldProxyVeracode());
        map.put("QualysRemoteProvider", getShouldProxyQualys());
        map.put("TrustwaveHailstormRemoteProvider", getShouldProxyTrustwaveHailstorm());
        return map;
    }

    @Column
    public Boolean getShouldProxyWhiteHat() {
        return shouldProxyWhiteHat == null || shouldProxyWhiteHat;
    }

    public void setShouldProxyWhiteHat(Boolean shouldProxyWhiteHat) {
        this.shouldProxyWhiteHat = shouldProxyWhiteHat;
    }

    @Column
    public Boolean getShouldProxyVeracode() {
        return shouldProxyVeracode == null || shouldProxyVeracode;
    }

    public void setShouldProxyVeracode(Boolean shouldProxyVeracode) {
        this.shouldProxyVeracode = shouldProxyVeracode;
    }

    @Column
    public Boolean getShouldProxyQualys() {
        return shouldProxyQualys == null || shouldProxyQualys;
    }

    public void setShouldProxyQualys(Boolean shouldProxyQualys) {
        this.shouldProxyQualys = shouldProxyQualys;
    }

    @Column
    public Boolean getShouldProxyTFS() {
        return shouldProxyTFS == null || shouldProxyTFS;
    }

    public void setShouldProxyTFS(Boolean shouldProxyTFS) {
        this.shouldProxyTFS = shouldProxyTFS;
    }

    @Column
    public Boolean getShouldProxyBugzilla() {
        return shouldProxyBugzilla == null || shouldProxyBugzilla;
    }

    public void setShouldProxyBugzilla(Boolean shouldProxyBugzilla) {
        this.shouldProxyBugzilla = shouldProxyBugzilla;
    }

    @Column
    public Boolean getShouldProxyJira() {
        return shouldProxyJira == null || shouldProxyJira;
    }

    public void setShouldProxyJira(Boolean shouldProxyJira) {
        this.shouldProxyJira = shouldProxyJira;
    }

    @Column
    public Boolean getShouldProxyVersionOne() {
        return shouldProxyVersionOne == null || shouldProxyVersionOne;
    }

    public void setShouldProxyVersionOne(Boolean shouldProxyVersionOne) {
        this.shouldProxyVersionOne = shouldProxyVersionOne;
    }

    @Column
    public Boolean getShouldProxyHPQC() {
        return shouldProxyHPQC == null || shouldProxyHPQC;
    }

    public void setShouldProxyHPQC(Boolean shouldProxyHPQC) {
        this.shouldProxyHPQC = shouldProxyHPQC;
    }

    @Column
    public Boolean getShouldUseProxyCredentials() {
        return shouldUseProxyCredentials;
    }

    public void setShouldUseProxyCredentials(Boolean shouldUseProxyCredentials) {
        this.shouldUseProxyCredentials = shouldUseProxyCredentials;
    }

    Boolean shouldProxyVeracode = false;
    Boolean shouldProxyQualys = false;
    Boolean shouldProxyTFS = false;
    Boolean shouldProxyBugzilla = false;
    Boolean shouldProxyJira = false;
    Boolean shouldProxyVersionOne = false;
    Boolean shouldProxyHPQC = false;
    Boolean shouldProxyWhiteHat = false;
    Boolean shouldUseProxyCredentials = false;
    Boolean shouldProxyTrustwaveHailstorm = false;

    @Column
    public Boolean getShouldProxyTrustwaveHailstorm() {
        return shouldProxyTrustwaveHailstorm;
    }

    public void setShouldProxyTrustwaveHailstorm(Boolean shouldProxyTrustwaveHailstorm) {
        this.shouldProxyTrustwaveHailstorm = shouldProxyTrustwaveHailstorm;
    }
}
