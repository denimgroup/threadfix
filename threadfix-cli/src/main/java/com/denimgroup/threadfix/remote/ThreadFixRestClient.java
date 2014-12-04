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

package com.denimgroup.threadfix.remote;

import com.denimgroup.threadfix.VulnerabilityInfo;
import com.denimgroup.threadfix.data.entities.*;
import com.denimgroup.threadfix.remote.response.RestResponse;

import java.util.Date;
import java.util.List;

/**
 * Created with IntelliJ IDEA.
 * User: stran
 * Date: 11/19/13
 * Time: 3:27 PM
 * To change this template use File | Settings | File Templates.
 */
public interface ThreadFixRestClient {

    public RestResponse<String> getRules(String wafId, String appId);
    public RestResponse<Waf> searchForWafByName(String name);
    public RestResponse<Waf> searchForWafById(String wafId);
    public RestResponse<Waf> createWaf(String name, String type);

    public RestResponse<Application> addWaf(String appId, String wafId);
    public RestResponse<Application> createApplication(String teamId, String name, String url);
    public RestResponse<Application> setParameters(String appId, String frameworkType, String repositoryUrl);
    public RestResponse<Application> searchForApplicationById(String id);
    public RestResponse<Application> searchForApplicationByName(String name, String teamName);

    public RestResponse<Organization[]> getAllTeams();
    public RestResponse<Organization> createTeam(String name);
    public RestResponse<String> getAllTeamsPrettyPrint();
    public RestResponse<Organization> searchForTeamById(String id);
    public RestResponse<Organization> searchForTeamByName(String name);

    // Information about these methods can be found on the wiki.
    // https://github.com/denimgroup/threadfix/wiki/Command-Line-Interface
    public RestResponse<VulnerabilityInfo[]> searchVulnerabilities(List<Integer> genericVulnerabilityIds,
               List<Integer> teamIds, List<Integer> applicationIds,
               List<String> scannerNames, List<Integer> genericSeverityValues, Integer numberVulnerabilities,
               String parameter, String path, Date startDate, Date endDate, Boolean showOpen, Boolean showClosed,
               Boolean showFalsePositive, Boolean showHidden, Integer numberMerged, Boolean showDefectPresent,
               Boolean showDefectNotPresent, Boolean showDefectOpen, Boolean showDefectClosed);

    public void setKey(String key);
    public void setUrl(String url);
    public void setMemoryKey(String key);
    public void setMemoryUrl(String url);

    public RestResponse<Scan> uploadScan(String applicationId, String filePath);
    public RestResponse<Application> addAppUrl(String appId, String url);

    public RestResponse<ScanQueueTask> queueScan(String applicationId, String scannerType);
    public RestResponse<Task> requestTask(String scanners, String agentConfig);
    public RestResponse<String> taskStatusUpdate(String scanQueueTaskId, String message);
    public RestResponse<String> setTaskConfig(String appId, String scannerType, String filePath);
    public RestResponse<ScanQueueTask> completeTask(String scanQueueTaskId, String filePath, String secureTaskKey);
    public RestResponse<String> failTask(String scanQueueTaskId, String message, String secureTaskKey);


    // QA only
    public RestResponse<User> createUser(String username, String globalRoleName);
    // QA only
    public RestResponse<User> createUser(String username);
    // QA only
    public RestResponse<User> addUserTeamAppPermission(String userName, String roleName, String teamName, String appName);


    // QA only
    public RestResponse<Role> createRole(String roleName, Boolean allPermissions);
    // QA only
    public RestResponse<Role> createSpecificPermissionRole(String roleName, String permission);
    // QA only
    public RestResponse<Role> removePermission(String roleName, String permission);

    // QA only
    public RestResponse<Tag> createTag(String tagname);
    // QA only
    public RestResponse<Tag> attachAppToTag(String tagname, String appname, String teamname);

    public RestResponse<Finding> addDynamicFinding(String applicationId, String vulnType, String severity,
                                    String nativeId, String parameter, String longDescription,
                                    String fullUrl, String path);
    public RestResponse<Finding> addStaticFinding(String applicationId, String vulnType, String severity,
                                   String nativeId, String parameter, String longDescription,
                                   String filePath, String column, String lineText, String lineNumber);
}
