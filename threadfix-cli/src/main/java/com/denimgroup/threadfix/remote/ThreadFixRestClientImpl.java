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
package com.denimgroup.threadfix.remote;

import com.denimgroup.threadfix.VulnerabilityInfo;
import com.denimgroup.threadfix.data.entities.*;
import com.denimgroup.threadfix.logging.SanitizedLogger;
import com.denimgroup.threadfix.properties.PropertiesManager;
import com.denimgroup.threadfix.remote.response.RestResponse;

import java.io.File;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Map;

public class ThreadFixRestClientImpl implements ThreadFixRestClient {

    private static final SanitizedLogger LOGGER = new SanitizedLogger(ThreadFixRestClientImpl.class);

    final HttpRestUtils httpRestUtils;
    final PropertiesManager propertiesManager;

	/**
	 * Default constructor that will read configuration from a local .properties file
	 */
	public ThreadFixRestClientImpl() {
        propertiesManager = new PropertiesManager();
        httpRestUtils = new HttpRestUtils(propertiesManager);
	}

    public ThreadFixRestClientImpl(PropertiesManager manager) {
        propertiesManager = manager;
        httpRestUtils = new HttpRestUtils(propertiesManager);
    }

	/**
	 * Custom constructor for when you want to use the in-memory properties
	 * 
	 * @param url URL for the ThreadFix server
	 * @param apiKey API key to use when accessing the ThreadFix server
	 */
	public ThreadFixRestClientImpl(String url, String apiKey) {
        propertiesManager = new PropertiesManager();
        propertiesManager.setMemoryKey(apiKey);
        propertiesManager.setMemoryUrl(url);
        httpRestUtils = new HttpRestUtils(propertiesManager);
	}
	
	public RestResponse<Application> createApplication(String teamId, String name, String url) {
        return httpRestUtils.httpPost("/teams/" + teamId + "/applications/new",
                new String[] { "name", "url"},
                new String[] {  name,   url},
                Application.class);
	}
	
	public RestResponse<Application> setParameters(String appId, String frameworkType, String repositoryUrl) {
		return httpRestUtils.httpPost("/applications/" + appId + "/setParameters",
				new String[] {"frameworkType", "repositoryUrl"},
				new String[] { frameworkType,   repositoryUrl},
                Application.class);
	}
	
	public RestResponse<Organization> createTeam(String name) {
		return httpRestUtils.httpPost("/teams/new",
				new String[] {"name"},
				new String[] { name },
                Organization.class);
	}
	
	public RestResponse<String> getRules(String wafId, String appId) {
		return httpRestUtils.httpGet("/wafs/" + wafId + "/rules" + "/app/" + appId, String.class);
	}

	public RestResponse<Waf> searchForWafByName(String name) {
		return httpRestUtils.httpGet("/wafs/lookup", "&name=" + name, Waf.class);
	}
	
	public RestResponse<Waf> searchForWafById(String wafId) {
		return httpRestUtils.httpGet("/wafs/" + wafId, Waf.class);
	}
	
	public RestResponse<Waf> createWaf(String name, String type) {
		return httpRestUtils.httpPost("/wafs/new",
				new String[] {"name", "type"},
				new String[] { name,   type},
                Waf.class);
	}
	
	/**
	 *
     * @param appId
     * @param wafId
     * @return
	 */
	public RestResponse<Application> addWaf(String appId, String wafId) {
        return httpRestUtils.httpPost("/applications/" + appId + "/setWaf",
                new String[]{"wafId"},
                new String[]{wafId},
                Application.class);
	}

	public RestResponse<Organization[]> getAllTeams() {
		return httpRestUtils.httpGet("/teams/", Organization[].class);
	}
    
    public RestResponse<String> getAllTeamsPrettyPrint() {
        final RestResponse<Organization[]> teams = getAllTeams();

        if (teams.success && teams.object.length > 0) {
            StringBuilder outputBuilder = new StringBuilder();

            for (Organization team : teams.object) {
                List<Application> applications = team.getApplications();

                if (team.isActive()) {
                    String teamName = team.getName();

                    if (!applications.isEmpty()) {
                        for (Application application : applications) {
                            boolean applicationActive = application.isActive();

                            if (applicationActive) {
                                String applicationName = application.getName();
                                Integer id = application.getId();

                                outputBuilder.append(teamName);
                                outputBuilder.append(";");
                                outputBuilder.append(applicationName);
                                outputBuilder.append(";");
                                outputBuilder.append(id);
                                outputBuilder.append("\n");
                            }
                        }
                    } else {
                        outputBuilder.append(teamName);
                        outputBuilder.append(": No Applications Found \n");
                    }
                }
            }

            if(outputBuilder.length() > 0){
                outputBuilder.setLength(outputBuilder.length() - 1);
            } else {
                outputBuilder.append("No applications");
            }

            String outputString = outputBuilder.toString();
            RestResponse<String> response = RestResponse.success(outputString);
            response.setJsonString(outputString);

            return response;
        } else {
            return RestResponse.failure("No Teams found.");
        }
    }	

	public RestResponse<Application> searchForApplicationById(String id) {
		return httpRestUtils.httpGet("/applications/" + id, Application.class);
	}

	public RestResponse<Application> searchForApplicationByName(String name, String teamName) {
		return httpRestUtils.httpGet("/applications/" + teamName + "/lookup",
				"&name=" + name, Application.class);
	}

    public RestResponse<Application[]> searchForApplicationByUniqueId(String uniqueId, String teamName) {
        return httpRestUtils.httpGet("/applications/" + teamName + "/lookup",
                "&uniqueId=" + uniqueId, Application[].class);
    }

	public RestResponse<Organization> searchForTeamById(String id) {
		return httpRestUtils.httpGet("/teams/" + id, Organization.class);
	}
	
	public RestResponse<Organization> searchForTeamByName(String name) {
		return httpRestUtils.httpGet("/teams/lookup", "&name=" + name, Organization.class);
    }

    public void setKey(String key) {
        propertiesManager.setKey(key);
	}

	public void setUrl(String url) {
        propertiesManager.setUrl(url);
	}
	
	public void setMemoryKey(String key) {
        propertiesManager.setMemoryKey(key);
	}
	
	public void setMemoryUrl(String url) {
        propertiesManager.setMemoryUrl(url);
	}
	
	public RestResponse<Scan> uploadScan(String applicationId, String filePath) {
		return httpRestUtils.httpPostFile("/applications/" + applicationId + "/upload",
                new File(filePath), new String[]{}, new String[]{}, Scan.class);
	}
	
	public RestResponse<ScanQueueTask> queueScan(String applicationId, String scannerType) {
        return queueScan(applicationId, scannerType, null);
	}

    @Override
    public RestResponse<ScanQueueTask> queueScan(String applicationId, String scannerType, String scanConfigId) {
        return httpRestUtils.httpPost("/tasks/queueScan",
                new String[] { "applicationId", "scannerType", "scanConfigId" },
                new String[] { applicationId, scannerType, scanConfigId },
                ScanQueueTask.class);
    }

    public RestResponse<Application> addAppUrl(String appId, String url) {
		return httpRestUtils.httpPost("/applications/" + appId + "/addUrl",
				new String[] {"url"},
				new String[] { url },
                Application.class);
	}
	
	public RestResponse<String> setTaskConfig(String appId, String scannerType, String filePath) {
		String url = "/tasks/setTaskConfig";
		String[] paramNames 	= {	"appId", "scannerType" };
		String[] paramValues 	= { appId, scannerType };
		return httpRestUtils.httpPostFile(url, new File(filePath), paramNames, paramValues, String.class);
	}
	
	public RestResponse<Finding> addDynamicFinding(String applicationId, String vulnType, String severity,
		String nativeId, String parameter, String longDescription,
		String fullUrl, String path) {
		return httpRestUtils.httpPost("/applications/" + applicationId +
                        "/addFinding",
                new String[]{"vulnType", "severity",
                        "nativeId", "parameter", "longDescription",
                        "fullUrl", "path"},
                new String[]{vulnType, severity,
                        nativeId, parameter, longDescription,
                        fullUrl, path}, Finding.class);
	}
	
	public RestResponse<Finding> addStaticFinding(String applicationId, String vulnType, String severity,
			String nativeId, String parameter, String longDescription,
			String filePath, String column, String lineText, String lineNumber) {
		return httpRestUtils.httpPost("/applications/" + applicationId +
                        "/addFinding",
                new String[]{"vulnType", "severity",
                        "nativeId", "parameter", "longDescription",
                        "filePath", "column", "lineText", "lineNumber"},
                new String[]{vulnType, severity,
                        nativeId, parameter, longDescription,
                        filePath, column, lineText, lineNumber}, Finding.class);
	}

    @Override
    public RestResponse<Tag> createTag(String name, String tagType) {
        return httpRestUtils.httpPost("/tags/new",
                new String[] { "name", "tagType" },
                new String[] { name, tagType }, Tag.class);
    }

    @Override
    public RestResponse<Tag> searchTagById(String id) {
        return httpRestUtils.httpGet("/tags/" + id, Tag.class);
    }

    @Override
    public RestResponse<Tag[]> searchTagsByName(String name) {
        return httpRestUtils.httpGet("/tags/lookup", "&name=" + name, Tag[].class);
    }

    @Override
    public RestResponse<Map> getAllTags() {
        return httpRestUtils.httpGet("/tags/index", Map.class);
    }

    @Override
    public RestResponse<Application> addAppTag(String appId, String tagId) {
        return httpRestUtils.httpPost("/applications/" + appId + "/tags/add/" + tagId, new String[]{}, new String[]{}, Application.class);
    }

    @Override
    public RestResponse<Application> removeAppTag(String appId, String tagId) {
        return httpRestUtils.httpPost("/applications/" + appId + "/tags/remove/" + tagId, new String[]{}, new String[]{}, Application.class);
    }

    @Override
    public RestResponse<Tag> updateTag(String tagId, String name) {
        return httpRestUtils.httpPost("/tags/" + tagId + "/update",
                new String[] {"name" },
                new String[] { name }, Tag.class);
    }

    @Override
    public RestResponse<String> removeTag(String tagId) {
        return httpRestUtils.httpPost("/tags/" + tagId + "/delete",
                new String[] { },
                new String[] { }, String.class);
    }

    // TODO find a better way to serialize this into a VulnerabilitySearchParameters form.
    @Override
    public RestResponse<VulnerabilityInfo[]> searchVulnerabilities(List<Integer> genericVulnerabilityIds,
               List<Integer> teamIds, List<Integer> applicationIds, List<String> scannerNames,
               List<Integer> genericSeverityValues, Integer numberVulnerabilities, String parameter, String path,
               Date startDate, Date endDate, Boolean showOpen, Boolean showClosed, Boolean showFalsePositive,
               Boolean showHidden, Integer numberMerged, Boolean showDefectPresent, Boolean showDefectNotPresent,
               Boolean showDefectOpen, Boolean showDefectClosed) {
        List<String> paramNames  = new ArrayList<String>();
        List<String> paramValues = new ArrayList<String>();

        addArrayFields(genericVulnerabilityIds, "genericVulnerabilities", "id", paramNames, paramValues);
        addArrayFields(teamIds, "teams", "id", paramNames, paramValues);
        addArrayFields(applicationIds, "applications", "id", paramNames, paramValues);
        addArrayFields(genericSeverityValues, "genericSeverities", "intValue", paramNames, paramValues);
        addArrayFields(scannerNames, "channelTypes", "name", paramNames, paramValues);

        if (numberVulnerabilities != null) {
            paramNames.add("numberVulnerabilities");
            paramValues.add(numberVulnerabilities.toString());
        }

        if (parameter != null) {
            paramNames.add("parameter");
            paramValues.add(parameter);
        }

        if (path != null) {
            paramNames.add("path");
            paramValues.add(path);
        }

        if (startDate != null) {
            paramNames.add("startDate");
            paramValues.add(String.valueOf(startDate.getTime()));
        }

        if (endDate != null) {
            paramNames.add("endDate");
            paramValues.add(String.valueOf(endDate.getTime()));
        }

        if (showOpen != null) {
            paramNames.add("showOpen");
            paramValues.add(showOpen.toString());
        }

        if (showClosed != null) {
            paramNames.add("showClosed");
            paramValues.add(showClosed.toString());
        }

        if (showFalsePositive != null) {
            paramNames.add("showFalsePositive");
            paramValues.add(showFalsePositive.toString());
        }

        if (showHidden != null) {
            paramNames.add("showHidden");
            paramValues.add(showHidden.toString());
        }

        if (numberMerged != null) {
            paramNames.add("numberMerged");
            paramValues.add(numberMerged.toString());
        }

        assert paramNames.size() == paramValues.size() : "Mismatched param names and values. This probably won't work.";

        return httpRestUtils.httpPost("/vulnerabilities", paramNames.toArray(new String[paramNames.size()]),
                paramValues.toArray(new String[paramValues.size()]), VulnerabilityInfo[].class);
    }

    private void addArrayFields(List<?> ids, String key, String field, List<String> paramNames, List<String> paramValues) {
        if (ids != null) {
            for (int i = 0; i < ids.size(); i++) {
                paramNames.add(key + "[" + i + "]." + field);
                paramValues.add(String.valueOf(ids.get(i)));
            }
        }
    }

    @Override
    public void setUnsafeFlag(boolean unsafeFlag) {
        this.httpRestUtils.setUnsafeFlag(unsafeFlag);
    }

    @Override
    public RestResponse<String> addVulnComment(Integer vulnId, String comment, String commentTagIds) {
        return httpRestUtils.httpPost("/vulnerabilities/" + vulnId + "/addComment",
                new String[] { "comment", "commentTagIds" },
                new String[] { comment, commentTagIds }, String.class);
    }

}
