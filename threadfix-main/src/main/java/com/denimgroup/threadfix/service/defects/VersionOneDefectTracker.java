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
import com.denimgroup.threadfix.exception.DefectTrackerCommunicationException;
import com.denimgroup.threadfix.exception.RestUrlException;
import com.denimgroup.threadfix.logging.SanitizedLogger;
import com.denimgroup.threadfix.viewmodel.DynamicFormField;
import com.denimgroup.threadfix.service.defects.utils.MarshallingUtils;
import com.denimgroup.threadfix.service.defects.utils.RestUtils;
import com.denimgroup.threadfix.service.defects.utils.RestUtilsImpl;
import com.denimgroup.threadfix.service.defects.utils.versionone.Assets;
import com.denimgroup.threadfix.service.defects.utils.versionone.AttributeDefinition;
import com.denimgroup.threadfix.service.defects.utils.versionone.AttributeDefinitionParser;
import com.denimgroup.threadfix.viewmodel.ProjectMetadata;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.*;

import static com.denimgroup.threadfix.CollectionUtils.list;
import static com.denimgroup.threadfix.CollectionUtils.newMap;

/**
 * Created by stran on 3/25/14.
 */
public class VersionOneDefectTracker extends AbstractDefectTracker {

    private static final String CONTENT_TYPE = "application/xml";

    private List<String> parentProjects = list();
    List<AttributeDefinition> attributeDefinitions = list();
    List<DynamicFormField> dynamicFormFields = list();

    private static final SanitizedLogger LOG = new SanitizedLogger(VersionOneDefectTracker.class);

    RestUtils restUtils = RestUtilsImpl.getInstance(VersionOneDefectTracker.class);

    @Override
    public String createDefect(List<Vulnerability> vulnerabilities, DefectMetadata metadata) {
        Assets.Asset assetTemplate = getAssetTemplate();

        Map<String,Object> fieldsMap = metadata.getFieldsMap();
        if (fieldsMap == null) {
            LOG.warn("No defect information found. Returning without doing anything.");
            return null;
        }

        if(fieldsMap.get("Description") != null) {
            String preamble = metadata.getPreamble();
            metadata.setPreamble(preamble + "\n" + String.valueOf(fieldsMap.get("Description")));
        }

        String description = makeDescription(vulnerabilities, metadata);
        description = description.replaceAll("\n", "<br>");

        assetTemplate.getAttributes().add(createAttribute("Description", "set", description));
        if (fieldsMap.get("Timebox") != null)
            assetTemplate.getRelations().add(createTimeBoxRelation(getUrlWithRest() + "Timebox?where=Schedule.ScheduledScopes.Name='" +
                    getUrlEncodedProjectName() + "'&sel=Name", "Timebox", "set", fieldsMap.get("Timebox").toString()));

        fieldsMap.remove("Description");
        fieldsMap.remove("Timebox");

        getV1Data();

        if (fieldsMap != null) {
            for(Map.Entry<String, Object> entry : fieldsMap.entrySet()){
                AttributeDefinition entryDef = findAttributeDefinition(entry.getKey());
                if (entryDef != null) {
                    if (entryDef.getRelationType().equals("select")) {
                        addRelation(entryDef, assetTemplate, entry.getValue());
                    } else {
                        addAttribute(entryDef, assetTemplate, entry.getValue());
                    }
                } else {
                    LOG.warn("Was unable to find " + entry.getKey() + " information");
                }
            }
        }
        String defectXml = MarshallingUtils.unmarshal(Assets.Asset.class, assetTemplate);
        
        LOG.debug(defectXml);

        String result = restUtils.postUrlAsString(getUrlWithRest() + "Defect", defectXml, getUsername(), getPassword(), CONTENT_TYPE);

        if (result == null) {
            throw new DefectTrackerCommunicationException("ThreadFix was unable to submit a defect to the tracker.");
        }

        return getDefectNumber(result);
    }

    private AttributeDefinition findAttributeDefinition(String name) {
        for (AttributeDefinition attributeDefinition : attributeDefinitions) {
            if (attributeDefinition.getName().equals(name))
                return attributeDefinition;
        }
        return null;
    }

    private void addRelation(AttributeDefinition attributeDefinition, Assets.Asset assetTemplate, Object value) {
        assert attributeDefinition.getRelatedItemType() != null : "Related Item type parsing is broken.";

        String action = attributeDefinition.isMultiValue() ? "add" : "set";

        String url = getUrlWithRest() +
                attributeDefinition.getRelatedItemType()
                + "?sel=Name";

        if ("Theme".equals(attributeDefinition.getRelatedItemType())) {
            url = url + "&where=SecurityScope.Name='" +
                getUrlEncodedProjectName() + "'";
        }

        LOG.info("Adding " + attributeDefinition + " as relation.");
        assetTemplate.getRelations().add(createRelation(attributeDefinition, attributeDefinition.getName(), action, value));
    }

    private void addAttribute(AttributeDefinition attributeDefinition, Assets.Asset assetTemplate, Object values) {
        LOG.info("Adding " + attributeDefinition.getName() + " as attribute.");

        String action = attributeDefinition.isMultiValue() ? "add" : "set";

        assetTemplate.getAttributes().add(
                createAttribute(attributeDefinition.getName(), action, values));
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

        List<String> defectNumberList = getAttributeNumber(getUrlWithRest() +
                "Defect?where=Scope.Name='" + getUrlEncodedProjectName() + "'&sel=Number", null);

        List<Defect> defectList = list();
        Defect defect;
        for (String number: defectNumberList) {
            defect = new Defect();
            defect.setNativeId(number);
            defectList.add(defect);
        }

        return defectList;
    }

    @Override
    @Nonnull
    public List<String> getProductNames() {
        lastError = null;
        List<String> projectList = getProjectList();

        if (projectList.isEmpty()) {
            if (!hasValidUrl()) {
                lastError = "Supplied endpoint was invalid.";
            } else if (!hasValidCredentials()) {
                lastError = "Invalid username / password combination";
            } else if (projectList.isEmpty()) {
                lastError = "No projects were found. Check your VersionOne instance.";
            } else {
                lastError = "Not sure what the error is.";
            }
        }
        return projectList;
    }

    @Override
    public String getProjectIdByName() {
        List<Assets.Asset> assetList = getAssets(getUrlWithRest() +
                    "Scope?where=Scope.Name='" + getUrlEncodedProjectName() + "'");
        if (assetList != null && !assetList.isEmpty()) {
            return assetList.get(0).getId();
        }
        log.error("Couldn't find id for VersionOne project");
        return null;
    }

    @Override
    public ProjectMetadata getProjectMetadata() {
        getV1Data();
        return new ProjectMetadata(dynamicFormFields);
    }

    private void getV1Data() {
        retrieveParentProjects();

        String attributesXML = restUtils.getUrlAsString(getMetaEndpoint(), getUsername(), getPassword());
        LOG.debug(attributesXML);
        attributeDefinitions = AttributeDefinitionParser.parseRequiredAttributes(attributesXML);
        dynamicFormFields = convertToGenericField(attributeDefinitions);

    }

    private List<DynamicFormField> convertToGenericField(List<AttributeDefinition> attributeDefinitions) {
        List<DynamicFormField> dynamicFormFields = list();
        for (AttributeDefinition attr : attributeDefinitions) {
            DynamicFormField genericField = new DynamicFormField();
            genericField.setActive(true);
            genericField.setEditable(!attr.isReadOnly());
            genericField.setLabel(attr.getName());
            genericField.setName(attr.getName());
            genericField.setType(attr.getRelationType());
            genericField.setRequired(attr.isRequired());
            genericField.setSupportsMultivalue(attr.isMultiValue());
            genericField.setOptionsMap(getFieldOptions(attr));

            genericField.setError("required", "This field cannot be empty.");

            dynamicFormFields.add(genericField);
        }

        return dynamicFormFields;
    }

    private Map<String, String> getFieldOptions(AttributeDefinition attr) {
        Map<String, String> optionMap = newMap();
        List<String> options;

        if (attr.getRelationType() != null && attr.getRelationType().equals("select")) {

            String relatedAsset = attr.getRelatedItemType();
            if (relatedAsset != null && !relatedAsset.isEmpty()) {
                if (relatedAsset.equals("Timebox")) {
                    options = getAttributeName(getUrlWithRest() + relatedAsset + "?where=Schedule.ScheduledScopes.Name='" + urlEncode(getProjectName()) + "'", attr);
                } else {
                    options = getAttributeName(getUrlWithRest() + relatedAsset + "?" + getWhereQuery("Scope.Name"), attr);
                }
                for (String v: options)
                    optionMap.put(v, v);
            }

        }
        return optionMap;
    }

    private String getWhereQuery(String assetName) {
        StringBuilder builder = new StringBuilder();
        builder.append("where=");
        for (String project : parentProjects) {
            builder.append(assetName).append("='").append(urlEncode(project)).append("'|");
        }
        builder.append(assetName).append("='").append(urlEncode(getProjectName())).append("'");
        return builder.toString();
    }

    private void retrieveParentProjects() {
        List<Assets.Asset> assetList = getAssets(getUrlWithRest() + "Scope?sel=Name,Parent.Name");
        findParent(assetList, getProjectName());
    }

    private void findParent(List<Assets.Asset> assetList, String childProject) {
        if (assetList == null || assetList.size() == 0)
            return;
        for (Assets.Asset asset: assetList) {
            if (asset.isAssetHasAttr("Name", childProject)) {
                Assets.Asset.Attribute parentAttr = asset.getAttributeByName("Parent.Name");
                List<String> parents = list();
                parents.addAll(parentAttr.getValues());
                parents.addAll(parentAttr.getMixed());
                if (parents.size() == 0)
                    return;
                parentProjects.addAll(parents);
                for (String p: parents)
                    findParent(assetList, p);
            }
        }
    }

    @Override
    public boolean hasValidCredentials() {
        log.info("Checking VersionOne credentials.");
        lastError = null;

        String response = restUtils.getUrlAsString(getUrlWithRest() + "Member?where=Username='" +
                getUrlEncodedUsername() + "'", getUsername(), getPassword());

        boolean valid = false;

        if (response == null) {
            lastError = "Null response was received from VersionOne server.";
            log.warn(lastError);
        } else if (!response.toLowerCase().contains(getUsername().toLowerCase())) {
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

        return projectList.contains(getProjectName());
    }

    @Override
    public boolean hasValidUrl() {
        log.info("Checking VersionOne Endpoint URL.");

        if (getUrlWithRest() == null) {
            log.info("URL was invalid.");
            return false;
        }

        boolean valid = restUtils.requestHas401Error(getUrlWithRest() + "Member");

        if (valid) {
            setLastError(BAD_URL);
            log.info("VersionOne URL was valid, returned 401 response as expected because we do not yet have credentials.");
        } else {
            log.warn("VersionOne URL was invalid or some other problem occurred, 401 response was expected but not returned.");
        }

        return valid;
    }

    private String getMetaEndpoint() {
        return getUrlWithExtension("meta.v1/Defect");
    }

    private String getUrlWithRest() {
        return getUrlWithExtension("rest-1.v1/Data");
    }

    private String getUrlWithExtension(String extension) {
        if (getUrl() == null || getUrl().trim().equals("")) {
            assert false : "We shouldn't be in this code path.";
            return null;
        }

        try {
            new URL(getUrl());
        } catch (MalformedURLException e) {
            throw new RestUrlException(e, "Invalid URL.");
        }

        if (getUrl().endsWith(extension + "/")) {
            return getUrl();
        }

        if (getUrl().endsWith(extension)) {
            return getUrl().concat("/");
        }

        String tempUrl = getUrl().trim();
        if (tempUrl.endsWith("/")) {
            tempUrl = tempUrl.concat(extension).concat("/");
        } else {
            tempUrl = tempUrl.concat("/").concat(extension).concat("/");
        }

        return tempUrl;
    }

    @Nonnull
    private List<String> getProjectList() {
        List<String> projectList = list();

        String result = restUtils.getUrlAsString(getUrlWithRest() +
                        "Member?where=Username='" + getUrlEncodedUsername() + "'&sel=Scopes",
                getUsername(), getPassword());
        if (result != null) {
            Assets assets = MarshallingUtils.marshal(Assets.class, result);
            if (assets != null && assets.getAssets() != null) {
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

        return projectList;
    }

    private List<Assets.Asset> getAssets(String url) {
        List<Assets.Asset> assetList = list();

        String result = restUtils.getUrlAsString(url, getUsername(), getPassword());
        if (result != null) {
            Assets assets = MarshallingUtils.marshal(Assets.class, result);
            if (assets != null && assets.getAssets() != null) {
                assetList = assets.getAssets();
            }
        }
        return assetList;
    }

    /**
     * Get attribute list of asset in given url
     * @param url
     * @return
     */
    private List<String> getAttributeName(String url, AttributeDefinition attr) {
        return getAttributes(url, attr, "Name");
    }

    /**
     * Get attribute list of asset in given url
     * @param url
     * @return
     */
    private List<String> getAttributeNumber(String url, AttributeDefinition attr) {
        return getAttributes(url, attr, "Number");
    }

    /**
     * Get attribute list of asset in given url
     * @param url
     * @return
     */
    private List<String> getAttributes(String url, AttributeDefinition attr, String fieldName) {
        List<String> attributes = new ArrayList<>();
        List<Assets.Asset> assetList = getAssets(url);
        if (attr != null)
            attr.setAssetList(assetList);
        for (Assets.Asset asset : assetList) {
            if (asset != null && asset.getAttributes() != null) {
                Assets.Asset.Attribute attribute = asset.getAttributeByName(fieldName);
                if (attribute != null) {
                    attributes.addAll(attribute.getValues());
                    attributes.addAll(attribute.getMixed());
                }
            }
        }
        return attributes;
    }

    /**
     *
     * @param attributeDefinition
     * @param name
     * @param act
     * @param values
     * @return
     */
    private Assets.Asset.Relation createRelation(@Nonnull AttributeDefinition attributeDefinition, String name, String act, Object values) {
        List<Assets.Asset> assetList = attributeDefinition.getAssetList();

        if (assetList.size() == 0) {
            LOG.warn("Asset list was empty for " + url + ". Integration will probably fail.");
        } else {

            List<Assets.Asset> targetAssets = list();
            Assets.Asset.Relation relation = new Assets.Asset.Relation();
            if (values == null)
                targetAssets.add(assetList.get(0));
            else {
                targetAssets = findAssets(assetList, values);
            }

            for (Assets.Asset targetAsset: targetAssets) {
                Assets.Asset assetRelation = new Assets.Asset();
                assetRelation.setHref(targetAsset.getHref());
                assetRelation.setIdref(targetAsset.getId());
                if (act.equals("add")) {
                    assetRelation.setAct("add");
                }

                LOG.info("Returning relation with href=" + targetAsset.getHref());


                if (act.equals("set")) {
                    relation.setAct("set");
                }

                relation.getAssetList().add(assetRelation);
            }
            relation.setName(name);
            return relation;
        }

        return null;
    }

    private List<Assets.Asset> findAssets(List<Assets.Asset> assetList, Object values) {

        List<Assets.Asset> targetAssets = list();

        if (values instanceof ArrayList) {
            for (Object value : (ArrayList) values) {
                for (Assets.Asset asset: assetList) {
                    if (asset.isAssetHasAttr("Name", String.valueOf(value)))
                        targetAssets.add(asset);

                }
            }
        } else {
            for (Assets.Asset asset: assetList) {
                if (asset.isAssetHasAttr("Name", String.valueOf(values)))
                    targetAssets.add(asset);

            }
        }
        return targetAssets;
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

    private Assets.Asset.Attribute createAttributeFromValues(String name, String act, String... values) {

        Assets.Asset.Attribute attribute = new Assets.Asset.Attribute();
        if (name != null)
            attribute.setName(name);
        if (act != null)
            attribute.setAct(act);
        if (values.length > 1) {
            attribute.setValues(list(values));
        } else {
            attribute.setMixed(list(values));
        }

        LOG.info("Returning attribute with values=" + Arrays.toString(values));

        return attribute;
    }

    private Assets.Asset.Attribute createAttribute(String name, String act, Object values) {

        if (values instanceof ArrayList) {
            List<String> strings = list();
            for (Object object : (ArrayList) values) {
                strings.add(object != null ? object.toString() : null);
            }
            String[] arr = new String[strings.size()];
            arr = strings.toArray(arr);
            return createAttributeFromValues(name, act, arr);
        } else {
            return createAttributeFromValues(name, act, String.valueOf(values));
        }
    }

    /**
     * Get Asset Template to create new Asset
     * @return
     */
    @Nonnull
    private Assets.Asset getAssetTemplate() {
        if (getProjectId() == null) {
            setProjectId(getProjectIdByName());
        }

        String result = restUtils.getUrlAsString(getUrlWithRest().replace("Data/", "") +
                "New/Defect?ctx=" + urlEncode(getProjectId()), getUsername(), getPassword());

        if (result == null) {
            throw new DefectTrackerCommunicationException("Received null response while attempting to get " +
                    "the asset information from the VersionOne server.");
        }

        return MarshallingUtils.marshal(Assets.Asset.class, result);
    }

    /**
     * Get Display Number of new defect just created
     * @param defectXml
     * @return
     */
    private String getDefectNumber(@Nonnull String defectXml) {

        String number = null;

        Assets.Asset asset = MarshallingUtils.marshal(Assets.Asset.class, defectXml);
        String id = asset.getId();
        if (id != null)
            id = id.replace(":","/");
        String numberXmlDefect = restUtils.getUrlAsString(getUrlWithRest() +
                id + "?sel=Number", getUsername(), getPassword());

        if (numberXmlDefect == null) {
            throw new DefectTrackerCommunicationException("Received null response from server.");
        }

        asset = MarshallingUtils.marshal(Assets.Asset.class, numberXmlDefect);
        if (asset != null && asset.getAttributes() != null
                && !asset.getAttributes().isEmpty()
                && asset.getAttributes().get(0).getMixed() != null
                && !asset.getAttributes().get(0).getMixed().isEmpty()) {
            number = asset.getAttributes().get(0).getMixed().get(0);
        }

        return number;
    }

    /**
     * Updating status for defect
     * @param defect
     * @return
     */
    @Nullable
    private String getStatus(@Nonnull Defect defect) {
        if (defect.getNativeId() == null) {
            log.warn("Bad defect passed to getStatus()");
            return null;
        }

        log.info("Updating status for defect " + defect.getNativeId());

        String nativeId = urlEncode(defect.getNativeId());
        List<String> result = getAttributes(getUrlWithRest() + "Defect?where=Number='" +
                nativeId + "'&sel=Status.Name", null, "Status.Name");

        if (!result.isEmpty()) {
            log.info("Current status for defect " +
                    nativeId + " is " + result.get(0));
            defect.setStatus(result.get(0));
            return result.get(0);
        } else {
            LOG.info("Current status for defect " + nativeId + " wasn't set, setting to 'Default'");
            defect.setStatus("Default");
            return "Default";
        }
    }
}
