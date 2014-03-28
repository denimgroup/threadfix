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
import com.denimgroup.threadfix.service.defects.VersionOne.Assets;
import org.json.JSONArray;
import org.json.JSONException;

import javax.xml.bind.JAXBException;
import java.io.UnsupportedEncodingException;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.URLEncoder;
import java.util.*;

/**
 * Created by stran on 3/25/14.
 */
public class VersionOneDefectTracker extends AbstractDefectTracker {

    private static final String CONTENT_TYPE = "application/xml";

    @Override
    public String createDefect(List<Vulnerability> vulnerabilities, DefectMetadata metadata) {
        Assets.Asset assetTemplate = getAssetTemplate();
        if (assetTemplate == null) {
            log.warn("Unable to get New Asset Template from VersionOne");
            return null;
        }
        assetTemplate.getAttributes().add(createAttribute("Name", "set", metadata.getDescription()));
        assetTemplate.getAttributes().add(createAttribute("Description", "set", makeDescription(vulnerabilities, metadata)));
        assetTemplate.getRelations().add(createTimeBoxRelation(getUrlWithRest() + "Timebox?where=Schedule.ScheduledScopes.Name='" +
                getProjectName() + "'&sel=Name", "Timebox", "set", metadata.getComponent()));
        assetTemplate.getRelations().add(createRelation(getUrlWithRest() + "List?where=AssetType='WorkitemPriority';Name='" +
                metadata.getPriority() + "'&sel=Name","Priority", "set"));
        assetTemplate.getRelations().add(createRelation(getUrlWithRest() + "List?where=AssetType='StoryStatus';Name='" +
                metadata.getStatus() + "'&sel=Name","Status", "set"));
        try {
            String defectXml = MarshallingUtils.unmarshal(Assets.Asset.class, assetTemplate);
            String result = RestUtils.postUrlAsString(getUrlWithRest() + "Defect",defectXml,getUsername(),getPassword(), CONTENT_TYPE);

            return getDefectNumber(result);
        } catch (Exception e) {
            log.error("Error when trying to unmarshal defect object to xml string", e);
        }
        return null;
    }

    @Override
    public String getBugURL(String endpointURL, String bugID) {
        return getUrlWithRest().replace("/rest-1.v1/Data/","");
    }

    @Override
    public Map<Defect, Boolean> getMultipleDefectStatus(List<Defect> defectList) {
        Map<Defect,Boolean> returnMap = new HashMap<>();

        if (defectList != null && defectList.size() != 0) {
            log.info("Updating VersionOne defect status for " + defectList.size() + " defects.");
            for (Defect defect : defectList) {
                if (defect != null) {
                    String result = getStatus(defect);
                    boolean isOpen = result != null && (!result.equals("Done"));
                    returnMap.put(defect, isOpen);
                }
            }
        } else {
            log.info("Tried to update defects but no defects were found.");
        }

        return returnMap;
    }

    @Override
    public List<Defect> getDefectList() {

        List<String> defectNumberList = getAttributes(getUrlWithRest() + "Defect?where=Scope.Name='" + getProjectName() + "'&sel=Number");

        List<Defect> defectList = new ArrayList<>();
        Defect defect;
        for (String number: defectNumberList) {
            defect = new Defect();
            defect.setNativeId(number);
            defectList.add(defect);
        }

        return defectList;

    }

    @Override
    public String getProductNames() {
        lastError = null;
        String projectNames = null;
        List<String> projectList = getProjectList();

        if (projectList != null) {
            StringBuilder builder = new StringBuilder();
            for (String project: projectList) {
                builder.append(project);
                builder.append(',');
            }
            if (builder.length()>0)
                projectNames = builder.substring(0,builder.length()-1);
        }

        if (projectNames == null) {
            if (!hasValidUrl()) {
                lastError = "Supplied endpoint was invalid.";
            } else if (!hasValidCredentials()) {
                lastError = "Invalid username / password combination";
            } else if (projectList != null) {
                lastError = "No projects were found. Check your VersionOne instance.";
            } else {
                lastError = "Not sure what the error is.";
            }
        }
        return projectNames;
    }

    @Override
    public String getProjectIdByName() {
        List<Assets.Asset> assetList = getAssets(getUrlWithRest() + "Scope?where=Scope.Name='" + getProjectName() + "'");
        if (assetList != null && !assetList.isEmpty()) {
            return assetList.get(0).getId();
        }
        log.warn("Couldn't find id for VersionOne project");
        return null;
    }

    @Override
    public ProjectMetadata getProjectMetadata() {

        List<String> sprints = getAttributes(getUrlWithRest() + "Timebox?where=Schedule.ScheduledScopes.Name='" + getProjectName() + "'&sel=Name");
        sprints.add(0,"");
        List<String> blankList = Arrays.asList("-");
        List<String> statusList = getAttributes(getUrlWithRest() + "List?where=AssetType='StoryStatus'&sel=Name");
        List<String> priorities = getAttributes(getUrlWithRest() + "List?where=AssetType='WorkitemPriority'&sel=Name");;

        return new ProjectMetadata(sprints, blankList,
                blankList, statusList, priorities);
    }

    @Override
    public boolean hasValidCredentials() {
        log.info("Checking VersionOne credentials.");
        lastError = null;

        String response = RestUtils.getUrlAsString(getUrlWithRest() + "Member?where=Username='" +
                getUsername() + "'", getUsername(), getPassword());

            boolean valid = false;

            if (response == null) {
                lastError = "Null response was received from VersionOne server.";
                log.warn(lastError);
            } else if (!response.contains(getUsername())) {
                lastError = "The returned name did not match the username.";
                log.warn(lastError);
            } else {
                valid = true;
            }
            return valid;
    }

    @Override
    public boolean hasValidProjectName() {
        if (getProjectName() == null)
            return false;
        List<String> projectList = getProjectList();
        if (projectList.contains(getProjectName())) {
            return true;
        }
        return false;
    }

    @Override
    public boolean hasValidUrl() {
        log.info("Checking VersionOne Endpoint URL.");

        if (getUrlWithRest() == null) {
            log.info("URL was invalid.");
            return false;
        }

        boolean valid = RestUtils.requestHas401Error(getUrlWithRest() + "Member");

        if (valid) {
            setLastError(BAD_URL);
            log.info("VersionOne URL was valid, returned 401 response as expected because we do not yet have credentials.");
        } else {
            log.warn("VersionOne URL was invalid or some other problem occurred, 401 response was expected but not returned.");
        }

        return valid;
    }

    private String getUrlWithRest() {
        if (getUrl() == null || getUrl().trim().equals("")) {
            return null;
        }

        try {
            new URL(getUrl());
        } catch (MalformedURLException e) {
            setLastError("The URL format was bad.");
            return null;
        }

        if (getUrl().endsWith("rest-1.v1/Data/")) {
            return getUrl();
        }

        if (getUrl().endsWith("rest-1.v1/Data")) {
            return getUrl().concat("/");
        }

        String tempUrl = getUrl().trim();
        if (tempUrl.endsWith("/")) {
            tempUrl = tempUrl.concat("rest-1.v1/Data/");
        } else {
            tempUrl = tempUrl.concat("/rest-1.v1/Data/");
        }

        return tempUrl;
    }

    private List<String> getProjectList() {
        List<String> projectList = null;

        String result = RestUtils.getUrlAsString(getUrlWithRest() + "Member?where=Username='" + getUsername() + "'&sel=Scopes",
                getUsername(), getPassword());
        try {
            if (result != null) {
                Assets assets = MarshallingUtils.marshal(Assets.class, result);
                if (assets != null && assets.getAssets() != null) {
                    projectList = new ArrayList<>();
                    for (Assets.Asset asset : assets.getAssets()) {
                        if (asset != null && asset.getAttributes() != null && asset.getAttributes().size() > 0) {
                            if (asset.getAttributes().get(0).getMixed() != null)
                                projectList.addAll(asset.getAttributes().get(0).getMixed());
                            if (asset.getAttributes().get(0).getValues() != null)
                                projectList.addAll(asset.getAttributes().get(0).getValues());
                        }
                    }
                }
            }
        } catch (JAXBException e) {
            log.warn("Unable to parse xml response");
        }
        return projectList;
    }

    private List<Assets.Asset> getAssets(String url) {
        List<Assets.Asset> assetList = new ArrayList<>();

        try {
            String result = RestUtils.getUrlAsString(url, getUsername(), getPassword());
            if (result != null) {
                Assets assets = MarshallingUtils.marshal(Assets.class, result);
                if (assets != null && assets.getAssets() != null) {
                    return assets.getAssets();
                }
            }
        } catch (JAXBException e) {
            log.warn("Unable to parse Assets xml response");
        }
        return assetList;
    }

    /**
     * Get attribute list of asset in given url
     * @param url
     * @return
     */
    private List<String> getAttributes(String url) {
        List<String> attributes = new ArrayList<>();
        List<Assets.Asset> assetList = getAssets(url);
        for (Assets.Asset asset : assetList) {
            if (asset != null && asset.getAttributes() != null)
                for (Assets.Asset.Attribute attribute: asset.getAttributes()) {
                    if (attribute.getValues() != null)
                        attributes.addAll(attribute.getValues());
                    if (attribute.getMixed() != null)
                        attributes.addAll(attribute.getMixed());
                }
        }
        return attributes;
    }

    /**
     * Create a relation in Defect
     * @param url
     * @param name
     * @param act
     * @return
     */
    private Assets.Asset.Relation createRelation(String url, String name, String act) {
        List<Assets.Asset> assetList = getAssets(url);
        for (Assets.Asset asset : assetList) {
            Assets.Asset assetRelation = new Assets.Asset();
            assetRelation.setHref(asset.getHref());
            assetRelation.setIdref(asset.getId());

            Assets.Asset.Relation relation = new Assets.Asset.Relation();
            relation.setAct(act);
            relation.setName(name);
            relation.getAssetList().add(assetRelation);
            return relation;
        }
        return null;
    }

    private Assets.Asset.Relation createTimeBoxRelation(String url, String name, String act, String timeBox) {
        List<Assets.Asset> assetList = getAssets(url);
        for (Assets.Asset asset : assetList) {
            if (asset.getAttributes() != null && !asset.getAttributes().isEmpty()
                    && asset.getAttributes().get(0).getMixed() != null
                    && !asset.getAttributes().get(0).getMixed().isEmpty()
                    && timeBox.equals(asset.getAttributes().get(0).getMixed().get(0))) {
                Assets.Asset.Relation relation = new Assets.Asset.Relation();
                relation.setAct(act);
                relation.setName(name);
                Assets.Asset assetRelation = new Assets.Asset();
                assetRelation.setHref(asset.getHref());
                assetRelation.setIdref(asset.getId());
                relation.getAssetList().add(assetRelation);
                return relation;
            }
        }
        return null;
    }

    private Assets.Asset.Attribute createAttribute(String name, String act, String... values) {

        Assets.Asset.Attribute attribute = new Assets.Asset.Attribute();
        if (name != null)
            attribute.setName(name);
        if (act != null)
            attribute.setAct(act);
        if (values.length > 1) {
            attribute.setValues(Arrays.asList(values));
        } else {
            attribute.setMixed(Arrays.asList(values));
        }

        return attribute;
    }

    /**
     * Get Asset Template to create new Asset
     * @return
     */
    private Assets.Asset getAssetTemplate() {
        if (getProjectId() == null) {
            setProjectId(getProjectIdByName());
        }
        String result = RestUtils.getUrlAsString(getUrlWithRest().replace("Data/","") + "New/Defect?ctx=" + getProjectId(), getUsername(), getPassword());

        try {
            if (result != null) {
                Assets.Asset assetTempate = MarshallingUtils.marshal(Assets.Asset.class, result);
                return assetTempate;
            }
        } catch (JAXBException e) {
            log.warn("Unable to parse Asset xml response");
        }
        return null;
    }

    /**
     * Get Display Number of new defect just created
     * @param defectXml
     * @return
     */
    private String getDefectNumber(String defectXml) {

        String number = null;

        try {
            Assets.Asset asset = MarshallingUtils.marshal(Assets.Asset.class, defectXml);
            String id = asset.getId();
            if (id != null)
                id = id.replace(":","/");
            String numberXmlDefect = RestUtils.getUrlAsString(getUrlWithRest() +
                    id + "?sel=Number", getUsername(), getPassword());
            asset = MarshallingUtils.marshal(Assets.Asset.class, numberXmlDefect);
            if (asset != null && asset.getAttributes() != null
                    && !asset.getAttributes().isEmpty()
                    && asset.getAttributes().get(0).getMixed() != null
                    && !asset.getAttributes().get(0).getMixed().isEmpty())
                number = asset.getAttributes().get(0).getMixed().get(0);

        } catch (JAXBException e) {
            log.warn("Unable to parse new Defect xml response");
        }

        return number;
    }

    /**
     * Updating status for defect
     * @param defect
     * @return
     */
    private String getStatus(Defect defect) {
        if (defect == null || defect.getNativeId() == null) {
            log.warn("Bad defect passed to getStatus()");
            return null;
        }

        log.info("Updating status for defect " + defect.getNativeId());

        List<String> result = getAttributes(getUrlWithRest() + "Defect?where=Number='" + defect.getNativeId() + "'&sel=Status.Name");
        if (!result.isEmpty()) {
            log.info("Current status for defect " + defect.getNativeId() + " is " + result.get(0));
            defect.setStatus(result.get(0));
            return result.get(0);
        }
        return null;
    }
}
