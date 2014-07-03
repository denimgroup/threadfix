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

package com.denimgroup.threadfix.service.defects;

import com.denimgroup.threadfix.data.entities.Defect;
import com.denimgroup.threadfix.data.entities.Vulnerability;
import com.denimgroup.threadfix.exception.DefectTrackerFormatException;
import com.denimgroup.threadfix.service.defects.utils.MarshallingUtils;
import com.denimgroup.threadfix.service.defects.utils.hpqc.HPQCUtils;
import com.denimgroup.threadfix.service.defects.utils.hpqc.infrastructure.Domains;
import com.denimgroup.threadfix.service.defects.utils.hpqc.infrastructure.Entity;

import javax.xml.bind.JAXBException;
import java.net.MalformedURLException;
import java.net.URL;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.*;

/**
 * Created by stran on 3/10/14.
 */
public class HPQualityCenterDefectTracker extends AbstractDefectTracker {
    @Override
    public String createDefect(List<Vulnerability> vulnerabilities, DefectMetadata metadata) {
        if (getProjectId() == null) {
            setProjectId(getProjectIdByName());
        }
        String description = makeDescription(vulnerabilities, metadata);
        Entity defect = new Entity();
        defect.setType("defect");
        defect.setFields(createFields(description, metadata));

        try {
            String defectXml = MarshallingUtils.unmarshal(Entity.class, defect);
            return HPQCUtils.postDefect(getHPQCUrl(), getUsername(), getPassword(), getProjectName(), defectXml);
        } catch (JAXBException e) {
            log.error("Error when trying to unmarshal defect object to xml string");
            throw new DefectTrackerFormatException(e,
                    "Unable to parse XML from server. More details can be found in the error logs.");
        }
    }

    private Entity.Fields createFields(String description, DefectMetadata metadata) {
        Entity.Fields fields = new Entity.Fields();
        fields.getField().add(createField("detected-by", getUsername()));
        DateFormat dateFormat = new SimpleDateFormat("yyyy-MM-dd");
        fields.getField().add(createField("creation-time", dateFormat.format(new Date())));
        fields.getField().add(createField("name", metadata.getDescription()));
        fields.getField().add(createField("severity", metadata.getSeverity()));
        if (metadata.getPriority() != null && !metadata.getPriority().isEmpty())
            fields.getField().add(createField("priority", metadata.getPriority()));
        if (metadata.getStatus() != null && !metadata.getStatus().isEmpty())
            fields.getField().add(createField("status", metadata.getStatus()));
        if (description != null && !description.isEmpty())
            fields.getField().add(createField("description", description));

        return fields;
    }

    private Entity.Fields.Field createField(String name, String value) {
        Entity.Fields.Field field = new Entity.Fields.Field();
        field.setName(name);
        field.getValue().add(value);
        return field;
    }

    @Override
    public String getBugURL(String endpointURL, String bugID) {
        return getHPQCUrl() + "/start_a.jsp";
    }

    @Override
    public Map<Defect, Boolean> getMultipleDefectStatus(List<Defect> defectList) {
        Map<Defect,Boolean> returnMap = new HashMap<>();

        if (defectList != null && defectList.size() != 0) {
            log.info("Updating HPQC defect status for " + defectList.size() + " defects.");
            returnMap = HPQCUtils.getStatuses(defectList, getHPQCUrl(), getUsername(), getPassword(), getProjectName());
        } else {
            log.info("Tried to update defects but no defects were found.");
        }

        return returnMap;

    }

    @Override
    public List<Defect> getDefectList() {

        return HPQCUtils.getDefectList(getHPQCUrl(), getUsername(), getPassword(), getProjectName());

    }

    @Override
    public String getProductNames() {
        log.info("Trying to get information from HP QC");
        String xmlResult = HPQCUtils.getAllProjects(getHPQCUrl(), username, password);
        String result = parseXml(xmlResult);

        if (result == null || result.isEmpty()) {
            if (!hasValidUrl()) {
                lastError = "Supplied endpoint was invalid.";
            } else if (xmlResult.contains("Authentication failed")) {
                lastError = "Authentication failed. Check username / password";
            } else {
                lastError = "No projects were found. Check your HP Quality Center instance.";
            }
        }

        return result;
    }

    private String parseXml(String xmlResult) {
        Domains domains;
        try {
            domains = MarshallingUtils.marshal(Domains.class, xmlResult);
            if (domains != null ) {
                StringBuilder builder = new StringBuilder();
                for (Domains.Domain domain : domains.getDomains()) {
                    if (domain != null) {
                        for (Domains.Domain.Projects.Project project : domain.getProjects().getProject()) {
                            if (project != null) {

                                log.info("Adding domain " + domain.getName() + " and project " + project.getProjectName());

                                builder.append(domain.getName()).append("/").append(project.getProjectName());
                                builder.append(',');
                            }
                        }
                    }
                }
                if (builder.length() > 0)
                    return builder.substring(0, builder.length() - 1);
            }
        } catch (JAXBException e) {
            log.warn("Marshalling the response failed due to JAXBException. The data was probably not XML.");
            log.debug("String was " + xmlResult);
        }
        return null;
    }

    @Override
    public String getProjectIdByName() {

        return projectName;
    }

    @Override
    public ProjectMetadata getProjectMetadata() {
        Map<String, List<String>> listValues = HPQCUtils.getListValues(getHPQCUrl(),username,password,projectName);

        List<String> versions = getValues(listValues, "Versions");
        if (!versions.contains("-")) {
            versions = new ArrayList<>(versions); // to avoid UnsupportedOperationException in next line
            versions.add("-");
        }

        return new ProjectMetadata(getValues(listValues, ""), versions,
                getValues(listValues, "Severity"), getValues(listValues, "Bug Status"), getValues(listValues, "Priority"));
    }

    private List<String> getValues(Map<String, List<String>> map, String key) {
        return (map == null || map.get(key) == null) ? Arrays.asList("-") : map.get(key);
    }

    @Override
    public String getTrackerError() {
        log.info("Attempting to find the reason that HPQC integration failed.");

        String reason;

        if (!hasValidUrl()) {
            reason =  "The HPQC url was incorrect.";
        } else if (!hasValidCredentials()) {
            reason =  "The supplied credentials or projects were incorrect.";
        } else {
            reason = "The HPQC integration failed but the " +
                    "cause is not the URL, credentials, or the Project Name.";
        }

        log.info(reason);
        return reason;
    }

    @Override
    public boolean hasValidCredentials() {
        return HPQCUtils.checkCredential(getHPQCUrl(),username,password,projectName);
    }

    @Override
    public boolean hasValidProjectName() {
        return true;
    }

    @Override
    public boolean hasValidUrl() {
        log.info("Checking HP Quality Center URL.");
        return HPQCUtils.checkUrl(getHPQCUrl());
    }

    /**
     * Checking format of URL input
     * @return HP Quality Center URL
     */
    private String getHPQCUrl() {
        if (getUrl() == null || getUrl().trim().equals("")) {
            return null;
        }

        try {
            new URL(getUrl());
        } catch (MalformedURLException e) {
            setLastError("The URL format was bad.");
            return null;
        }

        if (getUrl().endsWith("/qcbin")) {
            return getUrl();
        }

        if (getUrl().endsWith("/qcbin/")) {
            return getUrl().substring(0,getUrl().length()-1);
        }

        String tempUrl = getUrl().trim();
        if (tempUrl.endsWith("/")) {
            tempUrl = tempUrl.concat("qcbin");
        } else {
            tempUrl = tempUrl.concat("/qcbin");
        }

        return tempUrl;
    }

}
