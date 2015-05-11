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
package com.denimgroup.threadfix.service.report;

import com.denimgroup.threadfix.CollectionUtils;
import com.denimgroup.threadfix.data.dao.*;
import com.denimgroup.threadfix.data.entities.*;
import com.denimgroup.threadfix.data.entities.ReportParameters.ReportFormat;
import com.denimgroup.threadfix.logging.SanitizedLogger;
import com.denimgroup.threadfix.service.PermissionService;
import com.denimgroup.threadfix.service.VulnerabilitySearchService;
import com.denimgroup.threadfix.service.util.PermissionUtils;
import com.denimgroup.threadfix.webapp.controller.ReportCheckResultBean;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import javax.annotation.Nullable;
import javax.servlet.http.HttpServletRequest;
import java.text.SimpleDateFormat;
import java.util.*;

import static com.denimgroup.threadfix.CollectionUtils.list;
import static com.denimgroup.threadfix.CollectionUtils.map;
import static com.denimgroup.threadfix.util.CSVExportProperties.*;

/**
 * @author mcollins
 * @author drivera
 *
 */
@Service
public class ReportsServiceImpl implements ReportsService {

    private final SanitizedLogger log = new SanitizedLogger(ReportsServiceImpl.class);

    @Autowired
    private ScanDao           scanDao           = null;
    @Autowired
    private VulnerabilityDao  vulnerabilityDao  = null;
    @Autowired
    private GenericVulnerabilityDao  genericVulnerabilityDao  = null;
    @Autowired
    private OrganizationDao   organizationDao   = null;
    @Autowired
    private ApplicationDao    applicationDao    = null;
    @Autowired(required = false)
    @Nullable
    private PermissionService permissionService = null;
    @Autowired
    private VulnerabilitySearchService vulnerabilitySearchService;

    @Override
    public ReportCheckResultBean generateDashboardReport(ReportParameters parameters, HttpServletRequest request) {

        List<Integer> applicationIdList = getApplicationIdList(parameters);
        if (applicationIdList == null || applicationIdList.isEmpty()) {
            return new ReportCheckResultBean(ReportCheckResult.NO_APPLICATIONS);
        }

        ReportCheckResultBean report = null;

        if (parameters.getReportFormat() == ReportFormat.TOP_TEN_APPS) {
            applicationIdList = applicationDao.getTopXVulnerableAppsFromList(10, new ArrayList<Integer>(), applicationIdList);
            report = getTopAppsReportD3(applicationIdList);
        }
        if (parameters.getReportFormat() == ReportFormat.POINT_IN_TIME_GRAPH) {
            report = getPointInTimeD3(applicationIdList, parameters.getOrganizationId());
        }

        if (parameters.getReportFormat() == ReportFormat.TOP_TEN_VULNS) {
            List<Integer> vulnIds = vulnerabilityDao.getTopTenVulnTypes(applicationIdList);
            report = getTopVulnsReportD3(applicationIdList, vulnIds);
        }

        if (report == null || report.getReportList() == null || report.getReportList().size()==0)
            return new ReportCheckResultBean(ReportCheckResult.NO_APPLICATIONS);

        return report;
    }

    @Override
    public Map<String, Object> generateTrendingReport(ReportParameters parameters, HttpServletRequest request) {

        Map<String, Object> map = map();

        List<Integer> applicationIdList = getApplicationIdList(parameters);
        if (applicationIdList == null || applicationIdList.isEmpty()) {
            log.info("Unable to fill Report - no applications were found.");
            return map;
        }

        List<Scan> scanList = scanDao.retrieveByApplicationIdList(applicationIdList);
        if (scanList == null || scanList.isEmpty()) {
            log.info("Unable to fill Report - no scans were found.");
            return map;
        }
        map.put("scanList", scanList);

        return map;
    }

    @Override
    public Map<String, Object> generateSnapshotReport(ReportParameters parameters, HttpServletRequest request) {
        Map<String, Object> map = map();
        List<Integer> applicationIdList = getApplicationIdList(parameters);
        if (applicationIdList.isEmpty()) {
            log.info("No applications found.");
            return map;
        }
        map.put("vulnList", vulnerabilityDao.retrieveByApplicationIdList(applicationIdList));

        // Portfolio report
        List<Map<String, Object>> appList = list();
        for (Application application: applicationDao.retrieveAllActive()) {
            if (application.getScans() != null && application.getScans().size() > 0)
                appList.add(CollectionUtils.<String, Object>map(
                        "appId", application.getId(),
                        "appName", application.getName(),
                        "criticality", application.getApplicationCriticality().getName(),
                        "teamId", application.getOrganization().getId(),
                        "teamName", application.getOrganization().getName(),
                        "noOfScans", application.getScans().size(),
                        "latestScanTime", application.getScans().get(0).getImportTime(),
                        "tags", application.getTags()));
            else {
                appList.add(CollectionUtils.<String, Object>map(
                        "appId", application.getId(),
                        "appName", application.getName(),
                        "criticality", application.getApplicationCriticality().getName(),
                        "teamId", application.getOrganization().getId(),
                        "teamName", application.getOrganization().getName(),
                        "tags", application.getTags()));
            }
        }
        map.put("appList", appList);

        return map;
    }

    @Override
    public Map<String, Object> generateMostAppsReport(VulnerabilitySearchParameters parameters, HttpServletRequest request) {
        Map<String, Object> map = map();
        List<Integer> teamIdList = list();
        List<Integer> applicationIdList = list();
        List<Integer> tagIdList = list();

        vulnerabilitySearchService.applyPermissions(parameters);

        for (Organization organization: parameters.getTeams())
            teamIdList.add(organization.getId());

        for (Application application: parameters.getApplications())
            applicationIdList.add(application.getId());

        for (Tag tag: parameters.getTags())
            tagIdList.add(tag.getId());

        List<Integer> top20Apps = applicationDao.getTopXVulnerableAppsFromList(20, teamIdList, applicationIdList, tagIdList);
        map.put("appList", getTopAppsListInfo(top20Apps));
        return map;
    }

    private ReportCheckResultBean getTopVulnsReportD3(List<Integer> applicationIdList, List<Integer> vulnIds) {

        // to prevent exceptions on empty data
        if (vulnIds.isEmpty()) {
            vulnIds.add(0);
        }

        List<Object[]> vulns = vulnerabilityDao.getTopVulnsInfo(applicationIdList, vulnIds);
        List<Map<String, Object>> resultList = list();
        Application application = applicationDao.retrieveById(applicationIdList.get(0));
        for (Object[] objects: vulns) {
            if (objects != null && objects.length == 2) {

                if (!(objects[0] instanceof Integer)) continue;
                GenericVulnerability genericVulnerability = genericVulnerabilityDao.retrieveById((Integer) objects[0]);
                Map<String, Object> hash = map();
                hash.put("count", objects[1]);
                hash.put("title", "CWE-" + genericVulnerability.getDisplayId());
                hash.put("name", genericVulnerability.getName());
                hash.put("cweId", genericVulnerability.getId());
                hash.put("displayId", genericVulnerability.getDisplayId());
                hash.put("appId", applicationIdList.get(0));
                if (application != null){
                    hash.put("appName", application.getName());
                    hash.put("teamId", application.getOrganization().getId());
                    hash.put("teamName", application.getOrganization().getName());
                }

                resultList.add(hash);
            }
        }

        if (resultList.size() == 0 ) {
            log.info("Unable to fill Report - no vulns were found.");
            return null;
        } else {
            return new ReportCheckResultBean(ReportCheckResult.VALID, null, null, resultList);
        }

    }

    private ReportCheckResultBean getTopAppsReportD3(List<Integer> applicationIdList) {

        List<Map<String, Object>> resultList = getTopAppsListInfo(applicationIdList);

        if (resultList.size() == 0 ) {
            log.info("Unable to fill Report - no apps were found.");
            return null;
        } else {
            return new ReportCheckResultBean(ReportCheckResult.VALID, null, null, resultList);
        }
    }

    private List<Map<String, Object>> getTopAppsListInfo(List<Integer> applicationIdList) {
        List<Application> apps = applicationDao.getTopAppsFromList(applicationIdList);
        List<Map<String, Object>> resultList = list();
        for (Application app: apps) {
            Map<String, Object> hash = map();
            hash.put("Critical", app.getCriticalVulnCount());
            hash.put("High", app.getHighVulnCount());
            hash.put("Medium", app.getMediumVulnCount());
            hash.put("Low", app.getLowVulnCount());
            hash.put("Info", app.getInfoVulnCount());
            hash.put("appId", app.getId());
            hash.put("appName", app.getName());
            hash.put("teamId", app.getOrganization().getId());
            hash.put("teamName", app.getOrganization().getName());

            hash.put("title", app.getOrganization().getName() + "/" + app.getName());
            resultList.add(hash);
        }

        return resultList;
    }

    private ReportCheckResultBean getPointInTimeD3(List<Integer> applicationIdList, int teamId) {

        List<Object[]> objects = applicationDao.getPointInTime(applicationIdList);
        Organization team = organizationDao.retrieveById(teamId);
        List<Map<String, Object>> resultList = list();
        for (Object[] infoArr: objects) {
            Map<String, Object> hash = map();

            if (infoArr != null && infoArr.length >= 5) {
                hash.put("Critical", infoArr[4]);
                hash.put("High", infoArr[3]);
                hash.put("Medium", infoArr[2]);
                hash.put("Low", infoArr[1]);
                hash.put("Info", infoArr[0]);
                hash.put("teamId", teamId);
                if (team != null)
                    hash.put("teamName", team.getName());
            }
            resultList.add(hash);
        }

        if (resultList.size() == 0 ) {
            log.info("Unable to fill Report - no vulns were found.");
            return null;
        } else {
            return new ReportCheckResultBean(ReportCheckResult.VALID, null, null, resultList);
        }
    }

    private List<Integer> getApplicationIdList(ReportParameters reportParameters) {
        List<Integer> applicationIdList = list();
        Set<Integer> teamIds = null;
        if (permissionService == null) {
            teamIds = new HashSet<>();
            List<Organization> organizations = organizationDao.retrieveAllActive();

            if (organizations != null) {
                for (Organization organization : organizations) {
                    teamIds.add(organization.getId());
                }
            }
        } else {
            teamIds = permissionService.getAuthenticatedTeamIds();
        }

        if (reportParameters.getOrganizationId() < 0) {
            if (reportParameters.getApplicationId() < 0) {
                List<Application> appList;

                if (PermissionUtils.hasGlobalReadAccess()) {
                    appList = applicationDao.retrieveAllActive();
                } else if (teamIds == null || teamIds.size() == 0) {
                    appList = list();
                } else {
                    appList = applicationDao.retrieveAllActiveFilter(teamIds);
                }

                for (Application app : appList) {
                    applicationIdList.add(app.getId());
                }

                Set<Integer> appIds = PermissionUtils.getAuthenticatedAppIds();
                if (appIds != null && !appIds.isEmpty()) {
                    applicationIdList.addAll(appIds);
                }
            } else {
                applicationIdList.add(reportParameters.getApplicationId());
            }
        } else if (PermissionUtils.hasGlobalPermission(Permission.READ_ACCESS) ||
                teamIds.contains(reportParameters.getOrganizationId())) {
            Organization org = organizationDao.retrieveById(reportParameters.getOrganizationId());
            if (reportParameters.getApplicationId() < 0) {
                List<Application> appList = org.getActiveApplications();
                for (Application app : appList) {
                    if (app.isActive()) {
                        applicationIdList.add(app.getId());
                    }
                }
            } else {
                applicationIdList.add(reportParameters.getApplicationId());
            }
        }

        return applicationIdList;
    }

    @Override
    public ReportCheckResultBean generateSearchReport(List<Vulnerability> vulnerabilityList) {
        StringBuffer dataExport = getDataVulnListReport(getVulnListInfo(vulnerabilityList), null);
        return new ReportCheckResultBean(ReportCheckResult.VALID, dataExport, null);
    }

    private List<List<String>> getVulnListInfo(List<Vulnerability> vulnerabilityList) {
        List<List<String>> rowParamsList = list();
        SimpleDateFormat formatter = new SimpleDateFormat("yyyy-MM-dd");
        for (Vulnerability vuln : vulnerabilityList) {
            if (vuln == null) {
                continue;
            }

            String openedDate = formatter.format(vuln.getOpenTime().getTime());
            String description = "";

            for (Finding finding : vuln.getFindings()) {
                String longDescription = finding.getLongDescription();
                if (longDescription != null && !longDescription.isEmpty()) {
                    description = longDescription;
                    break;
                }
            }

            // create fields map
            Map<String, String> csvMap = map(
                    CWE_ID,              vuln.getGenericVulnerability().getId().toString(),
                    CWE_NAME,            vuln.getGenericVulnerability().getName(),
                    PATH,                vuln.getSurfaceLocation().getPath(),
                    PARAMETER,           vuln.getSurfaceLocation().getParameter(),
                    SEVERITY,            vuln.getGenericSeverity().getName(),
                    OPEN_DATE,           openedDate,
                    DESCRIPTION,         description,
                    DEFECT_ID,           (vuln.getDefect() == null) ? "" : vuln.getDefect().getNativeId(),
                    APPLICATION_NAME,    vuln.getApplication().getName(),
                    TEAM_NAME,           vuln.getApplication().getOrganization().getName(),
                    PAYLOAD,             vuln.getSurfaceLocation().getQuery() == null ? "" : vuln.getSurfaceLocation().getQuery(),
                    ATTACK_SURFACE_PATH, vuln.getSurfaceLocation().getUrl() == null ? "" : vuln.getSurfaceLocation().getUrl().toString()
            );

            // add configured fields only
            List<String> listToAdd = list();

            for (String headerKey : getCSVExportHeaderList()) {
                listToAdd.add(csvMap.get(headerKey));
            }

            rowParamsList.add(listToAdd);
        }
        return rowParamsList;
    }

    private StringBuffer getDataVulnListReport(List<List<String>> rowParamsList, List<Integer> applicationIdList) {
        StringBuffer data = new StringBuffer();
        data.append("Vulnerability List \n\n");

        if (applicationIdList != null) {

            List<String> teamNames = applicationDao.getTeamNames(applicationIdList);
            String teamName = (teamNames != null && teamNames.size() == 1) ? teamNames.get(0) : "All";
            data.append("Team: ").append(teamName).append(" \n");
            String appName = "";
            if (applicationIdList.size() == 1) {
                Application app = applicationDao.retrieveById(applicationIdList.get(0));
                if (app != null) {
                    appName = app.getName();
                }
            } else {
                appName = "All";
            }
            data.append("Application: ").append(appName).append(" \n \n");
        }

		data.append(getCSVExportHeaderString());
		for (List<String> row: rowParamsList) {
			for (int i=0;i<row.size();i++) {
				String str = "";
				if (row.get(i) != null) str = row.get(i);//

				if (str.contains(",")) {
                    str = "\"" + str.replaceAll("\"", "\"\"") + "\"";
                }
                if (str.contains("\n")) {
                    str = "\"" + str + "\"";
                }

				if (i<row.size()-1)
					data.append(str).append(",");
				else data.append(str).append(" \n");
			}
		}
		return data;
	}

}
