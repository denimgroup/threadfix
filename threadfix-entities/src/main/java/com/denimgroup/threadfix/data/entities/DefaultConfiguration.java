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
import com.fasterxml.jackson.annotation.JsonView;

import javax.persistence.*;
import java.io.File;
import java.util.Calendar;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static com.denimgroup.threadfix.CollectionUtils.list;

@Entity
@Table(name="DefaultConfiguration")
public class DefaultConfiguration extends BaseEntity {

	private static final long serialVersionUID = 2584623185996706729L;

    public static final String MASKED_PASSWORD = "dbnH3rDuZC2Nib";

	private Boolean globalGroupEnabled = null;
    private Boolean hasAddedScheduledImports = null;
    private Boolean hasAddedScheduledDefectTrackerUpdates = null;
    private Boolean hasAddedScheduledGRCToolUpdates = null;
    private Integer defaultRoleId = null;

    private Boolean hasCachedData = null;

	private String activeDirectoryBase, activeDirectoryURL, activeDirectoryUsername, activeDirectoryCredentials, activeDirectoryUsernameEncrypted, activeDirectoryCredentialsEncrypted;

    private String proxyHost = null, proxyUsername = null, proxyPassword = null, proxyUsernameEncrypted = null, proxyPasswordEncrypted = null;
    private Integer proxyPort = null;

    private Calendar lastScannerMappingsUpdate;

    private Integer sessionTimeout = null;

    private Report dashboardTopLeft, dashboardTopRight, dashboardBottomLeft,dashboardBottomRight,
            applicationTopLeft, applicationTopRight, teamTopLeft, teamTopRight;

    private String fileUploadLocation = null;

    public static DefaultConfiguration getInitialConfig() {
        DefaultConfiguration config = new DefaultConfiguration();
        config.setDefaultRoleId(1);
        config.setGlobalGroupEnabled(true);
        config.setHasAddedScheduledImports(false);
        config.setHasAddedScheduledDefectTrackerUpdates(false);
        config.setHasAddedScheduledGRCToolUpdates(false);
        return config;
    }

    @Column
    @JsonView(AllViews.FormInfo.class)
    public Integer getSessionTimeout() {
        return sessionTimeout;
    }

    public void setSessionTimeout(Integer sessionTimeout) {
        this.sessionTimeout = sessionTimeout;
    }

    @JsonView(AllViews.FormInfo.class)
    @Column(length = 1024, nullable = true)
    public String getFileUploadLocation() {
        return fileUploadLocation;
    }

    public void setFileUploadLocation(String fileUploadLocation) {
        this.fileUploadLocation = fileUploadLocation;
    }

    @Transient
    public boolean fileUploadLocationExists() {
        return fileUploadLocation != null && !fileUploadLocation.isEmpty();
    }

    @Transient
    public String getFullFilePath(Scan scan) {
        return fileUploadLocation + File.separator + scan.getFileName();
    }

    @OneToOne
    @JoinColumn(name = "teamTopLeftId")
    @JsonView(AllViews.FormInfo.class)
    public Report getTeamTopLeft() {
        return teamTopLeft;
    }

    public void setTeamTopLeft(Report teamTopLeft) {
        this.teamTopLeft = teamTopLeft;
    }

    @OneToOne
    @JoinColumn(name = "teamTopRightId")
    @JsonView(AllViews.FormInfo.class)
    public Report getTeamTopRight() {
        return teamTopRight;
    }

    public void setTeamTopRight(Report teamTopRight) {
        this.teamTopRight = teamTopRight;
    }

    @OneToOne
    @JoinColumn(name = "applicationTopLeftId")
    @JsonView(AllViews.FormInfo.class)
    public Report getApplicationTopLeft() {
        return applicationTopLeft;
    }

    public void setApplicationTopLeft(Report applicationTopLeft) {
        this.applicationTopLeft = applicationTopLeft;
    }

    @OneToOne
    @JoinColumn(name = "applicationTopRightId")
    @JsonView(AllViews.FormInfo.class)
    public Report getApplicationTopRight() {
        return applicationTopRight;
    }

    public void setApplicationTopRight(Report applicationTopRight) {
        this.applicationTopRight = applicationTopRight;
    }

    @OneToOne
    @JoinColumn(name = "dashboardTopLeftId")
    @JsonView(AllViews.FormInfo.class)
    public Report getDashboardTopLeft() {
        return dashboardTopLeft;
    }

    public void setDashboardTopLeft(Report dashboardTopLeft) {
        this.dashboardTopLeft = dashboardTopLeft;
    }

    @OneToOne
    @JoinColumn(name = "dashboardTopRightId")
    @JsonView(AllViews.FormInfo.class)
    public Report getDashboardTopRight() {
        return dashboardTopRight;
    }

    public void setDashboardTopRight(Report dashboardTopRight) {
        this.dashboardTopRight = dashboardTopRight;
    }

    @OneToOne
    @JoinColumn(name = "dashboardBottomLeftId")
    @JsonView(AllViews.FormInfo.class)
    public Report getDashboardBottomLeft() {
        return dashboardBottomLeft;
    }

    public void setDashboardBottomLeft(Report dashboardBottomLeft) {
        this.dashboardBottomLeft = dashboardBottomLeft;
    }

    @OneToOne
    @JoinColumn(name = "dashboardBottomRightId")
    @JsonView(AllViews.FormInfo.class)
    public Report getDashboardBottomRight() {
        return dashboardBottomRight;
    }

    public void setDashboardBottomRight(Report dashboardBottomRight) {
        this.dashboardBottomRight = dashboardBottomRight;
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
    public Boolean getHasAddedScheduledGRCToolUpdates() {
        return hasAddedScheduledGRCToolUpdates != null && hasAddedScheduledGRCToolUpdates;
    }

    public void setHasAddedScheduledGRCToolUpdates(Boolean hasAddedScheduledGRCToolUpdates){
        this.hasAddedScheduledGRCToolUpdates = hasAddedScheduledGRCToolUpdates;
    }

    @Column
    public Boolean getHasCachedData() {
        return hasCachedData != null && hasCachedData;
    }

    public void setHasCachedData(Boolean hasCachedData) {
        this.hasCachedData = hasCachedData;
    }

    @Column
    @JsonView(AllViews.FormInfo.class)
    public Integer getDefaultRoleId() {
        return defaultRoleId;
    }

    public void setDefaultRoleId(Integer defaultRoleId) {
        this.defaultRoleId = defaultRoleId;
    }

    @Column
    @JsonView(AllViews.FormInfo.class)
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

    @Column(length=256)
    @JsonView(AllViews.FormInfo.class)
	public String getActiveDirectoryURL() {
        return activeDirectoryURL == null ? "" : activeDirectoryURL;
	}

	public void setActiveDirectoryURL(String activeDirectoryURL) {
		this.activeDirectoryURL = activeDirectoryURL;
	}

    @Column(length=256)
    @JsonView(AllViews.FormInfo.class)
	public String getActiveDirectoryUsername() {
		return activeDirectoryUsername == null ? "" : activeDirectoryUsername;
	}

	@Column(length=256)
    @JsonView(AllViews.FormInfo.class)
    public String getActiveDirectoryBase() {
        return activeDirectoryBase == null ? "" : activeDirectoryBase;
    }

	public void setActiveDirectoryUsername(String activeDirectoryUsername) {
		this.activeDirectoryUsername = activeDirectoryUsername;
	}

    @JsonView(AllViews.FormInfo.class)
    public String getActiveDirectoryCredentials() {
		return activeDirectoryCredentials == null ? "" : activeDirectoryCredentials;
	}

    public void setActiveDirectoryCredentials(String activeDirectoryCredentials) {
        this.activeDirectoryCredentials = activeDirectoryCredentials;
    }

    @Column(length = 1024)
    public String getActiveDirectoryUsernameEncrypted() {
        return activeDirectoryUsernameEncrypted;
    }

    public void setActiveDirectoryUsernameEncrypted(String activeDirectoryUsernameEncrypted) {
        this.activeDirectoryUsernameEncrypted = activeDirectoryUsernameEncrypted;
    }

    @Column(length = 1024)
    public String getActiveDirectoryCredentialsEncrypted() {
        return activeDirectoryCredentialsEncrypted;
    }

    public void setActiveDirectoryCredentialsEncrypted(String activeDirectoryCredentialsEncrypted) {
        this.activeDirectoryCredentialsEncrypted = activeDirectoryCredentialsEncrypted;
    }

    @Column
    public Calendar getLastScannerMappingsUpdate() {
        return lastScannerMappingsUpdate;
    }

    public void setLastScannerMappingsUpdate(Calendar lastScannerMappingsUpdate) {
        this.lastScannerMappingsUpdate = lastScannerMappingsUpdate;
    }

    @Transient
    @JsonView(AllViews.FormInfo.class)
    public String getProxyUsername() {
        return proxyUsername;
    }

    public void setProxyUsername(String proxyUsername) {
        this.proxyUsername = proxyUsername;
    }

    @Transient
    @JsonView(AllViews.FormInfo.class)
    public String getProxyPassword() {
        return proxyPassword;
    }

    public void setProxyPassword(String proxyPassword) {
        this.proxyPassword = proxyPassword;
    }

    @Column(length = 1024)
    @JsonView(AllViews.FormInfo.class)
    public String getProxyUsernameEncrypted() {
        return proxyUsernameEncrypted;
    }

    public void setProxyUsernameEncrypted(String proxyUsernameEncrypted) {
        this.proxyUsernameEncrypted = proxyUsernameEncrypted;
    }

    @Column(length = 1024)
    @JsonView(AllViews.FormInfo.class)
    public String getProxyPasswordEncrypted() {
        return proxyPasswordEncrypted;
    }

    public void setProxyPasswordEncrypted(String proxyPasswordEncrypted) {
        this.proxyPasswordEncrypted = proxyPasswordEncrypted;
    }

    @Column
    @JsonView(AllViews.FormInfo.class)
    public Integer getProxyPort() {
        return proxyPort;
    }

    public void setProxyPort(Integer proxyPort) {
        this.proxyPort = proxyPort;
    }

    @Column(length = 1024)
    @JsonView(AllViews.FormInfo.class)
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
        Map<String, Boolean> proxySupportMap = getProxySupportMap();
        String key = classToProxy.getSimpleName();
        Boolean result = proxySupportMap.get(key);
        return result != null && result;
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
        map.put("ContrastRemoteProvider", getShouldProxyContrast());
        return map;
    }

    @Transient
    public List<Report> getDashboardReports() {
        List<Report> dashboardReports = list();

        dashboardReports.add(getDashboardTopLeft());
        dashboardReports.add(getDashboardTopRight());
        dashboardReports.add(getDashboardBottomLeft());
        dashboardReports.add(getDashboardBottomRight());

        return dashboardReports;
    }

    @Transient
    public List<Report> getApplicationReports() {
        List<Report> applicationReports = list();

        applicationReports.add(getApplicationTopLeft());
        applicationReports.add(getApplicationTopRight());

        return applicationReports;
    }

    @Transient
    public List<Report> getTeamReports() {
        List<Report> teamReports = list();

        teamReports.add(getTeamTopLeft());
        teamReports.add(getTeamTopRight());

        return teamReports;
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
    Boolean shouldProxyContrast = false;

    @Column
    @JsonView(AllViews.FormInfo.class)
    public Boolean getShouldProxyWhiteHat() {
        return shouldProxyWhiteHat == null || shouldProxyWhiteHat;
    }

    public void setShouldProxyWhiteHat(Boolean shouldProxyWhiteHat) {
        this.shouldProxyWhiteHat = shouldProxyWhiteHat;
    }

    @Column
    @JsonView(AllViews.FormInfo.class)
    public Boolean getShouldProxyVeracode() {
        return shouldProxyVeracode == null || shouldProxyVeracode;
    }

    public void setShouldProxyVeracode(Boolean shouldProxyVeracode) {
        this.shouldProxyVeracode = shouldProxyVeracode;
    }

    @Column
    @JsonView(AllViews.FormInfo.class)
    public Boolean getShouldProxyQualys() {
        return shouldProxyQualys == null || shouldProxyQualys;
    }

    public void setShouldProxyQualys(Boolean shouldProxyQualys) {
        this.shouldProxyQualys = shouldProxyQualys;
    }

    @Column
    @JsonView(AllViews.FormInfo.class)
    public Boolean getShouldProxyTFS() {
        return shouldProxyTFS == null || shouldProxyTFS;
    }

    public void setShouldProxyTFS(Boolean shouldProxyTFS) {
        this.shouldProxyTFS = shouldProxyTFS;
    }

    @Column
    @JsonView(AllViews.FormInfo.class)
    public Boolean getShouldProxyBugzilla() {
        return shouldProxyBugzilla == null || shouldProxyBugzilla;
    }

    public void setShouldProxyBugzilla(Boolean shouldProxyBugzilla) {
        this.shouldProxyBugzilla = shouldProxyBugzilla;
    }

    @Column
    @JsonView(AllViews.FormInfo.class)
    public Boolean getShouldProxyJira() {
        return shouldProxyJira == null || shouldProxyJira;
    }

    public void setShouldProxyJira(Boolean shouldProxyJira) {
        this.shouldProxyJira = shouldProxyJira;
    }

    @Column
    @JsonView(AllViews.FormInfo.class)
    public Boolean getShouldProxyVersionOne() {
        return shouldProxyVersionOne == null || shouldProxyVersionOne;
    }

    public void setShouldProxyVersionOne(Boolean shouldProxyVersionOne) {
        this.shouldProxyVersionOne = shouldProxyVersionOne;
    }

    @Column
    @JsonView(AllViews.FormInfo.class)
    public Boolean getShouldProxyHPQC() {
        return shouldProxyHPQC == null || shouldProxyHPQC;
    }

    public void setShouldProxyHPQC(Boolean shouldProxyHPQC) {
        this.shouldProxyHPQC = shouldProxyHPQC;
    }

    @Column
    @JsonView(AllViews.FormInfo.class)
    public Boolean getShouldUseProxyCredentials() {
        return shouldUseProxyCredentials;
    }

    public void setShouldUseProxyCredentials(Boolean shouldUseProxyCredentials) {
        this.shouldUseProxyCredentials = shouldUseProxyCredentials;
    }

    @Column
    @JsonView(AllViews.FormInfo.class)
    public Boolean getShouldProxyTrustwaveHailstorm() {
        return shouldProxyTrustwaveHailstorm == null || shouldProxyTrustwaveHailstorm;
    }

    public void setShouldProxyTrustwaveHailstorm(Boolean shouldProxyTrustwaveHailstorm) {
        this.shouldProxyTrustwaveHailstorm = shouldProxyTrustwaveHailstorm;
    }

    @Column
    @JsonView(AllViews.FormInfo.class)
    public Boolean getShouldProxyContrast() {
        return shouldProxyContrast == null || shouldProxyContrast;
    }

    public void setShouldProxyContrast(Boolean shouldProxyContrast) {
        this.shouldProxyContrast = shouldProxyContrast;
    }
}
