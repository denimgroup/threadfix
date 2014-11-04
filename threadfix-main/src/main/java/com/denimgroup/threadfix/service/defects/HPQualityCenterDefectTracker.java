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
import com.denimgroup.threadfix.data.entities.Finding;
import com.denimgroup.threadfix.data.entities.SurfaceLocation;
import com.denimgroup.threadfix.data.entities.Vulnerability;
import com.denimgroup.threadfix.service.defects.utils.DynamicFormField;
import com.denimgroup.threadfix.service.defects.utils.MarshallingUtils;
import com.denimgroup.threadfix.service.defects.utils.hpqc.HPQCUtils;
import com.denimgroup.threadfix.service.defects.utils.hpqc.infrastructure.*;

import javax.annotation.Nonnull;
import java.net.MalformedURLException;
import java.net.URL;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.*;

import static com.denimgroup.threadfix.CollectionUtils.list;
import static com.denimgroup.threadfix.CollectionUtils.newMap;

/**
 * Created by stran on 3/10/14.
 */
public class HPQualityCenterDefectTracker extends AbstractDefectTracker {

    private List<Fields.Field> editableFieldsList = list();
    private Map<String, List<String>> defectListMap = newMap();

    @Override
    public String createDefect(List<Vulnerability> vulnerabilities, DefectMetadata metadata) {
        if (getProjectId() == null) {
            setProjectId(getProjectIdByName());
        }

        editableFieldsList = HPQCUtils.getEditableFields(getHPQCUrl(), username, password, projectName);

        Map<String,Object> fieldsMap = metadata.getFieldsMap();
        if (fieldsMap.get("description") != null)
            metadata.setPreamble(String.valueOf(fieldsMap.get("description")));

        String description = makeDescription(vulnerabilities, metadata);
        fieldsMap.put("description", description);

        Entity defect = new Entity();
        defect.setType("defect");
        defect.setFields(createFields(fieldsMap));

        String defectXml = MarshallingUtils.unmarshal(Entity.class, defect);
        return HPQCUtils.postDefect(getHPQCUrl(), getUsername(), getPassword(), getProjectName(), defectXml);
    }

    @Override
    protected String makeDescription(List<Vulnerability> vulnerabilities, DefectMetadata metadata) {
        StringBuilder stringBuilder = new StringBuilder();

        String preamble = metadata.getPreamble();

        if (preamble != null && !"".equals(preamble)) {
            stringBuilder.append("General information\n");
            stringBuilder.append(preamble);
            stringBuilder.append('\n');
        }

        int vulnIndex = 0;

        if (vulnerabilities != null) {
            for (Vulnerability vulnerability : vulnerabilities) {
                if (vulnerability.getGenericVulnerability() != null &&
                        vulnerability.getSurfaceLocation() != null) {

                    stringBuilder
                            .append("Vulnerability[")
                            .append(vulnIndex)
                            .append("]:\n")
                            .append(vulnerability.getGenericVulnerability().getName())
                            .append('\n')
                            .append("CWE-ID: ")
                            .append(vulnerability.getGenericVulnerability().getId())
                            .append('\n')
                            .append("http://cwe.mitre.org/data/definitions/")
                            .append(vulnerability.getGenericVulnerability().getId())
                            .append(".html")
                            .append('\n');

                    SurfaceLocation surfaceLocation = vulnerability.getSurfaceLocation();
                    stringBuilder
                            .append("Vulnerability attack surface location:\n")
                            .append("URL: ")
                            .append(surfaceLocation.getUrl())
                            .append("\n")
                            .append("Parameter: ")
                            .append(surfaceLocation.getParameter());

                    List<Finding> findings = vulnerability.getFindings();
                    if (findings != null && !findings.isEmpty()) {
                        addUrlReferences(findings, stringBuilder);
                        addNativeIds(findings, stringBuilder);
                    }

                    stringBuilder.append("\n\n");
                    vulnIndex++;
                }
            }
        }
        return stringBuilder.toString();
    }

    private Entity.Fields createFields(Map<String,Object> fieldsMap) {
        Entity.Fields fields = new Entity.Fields();
        if (fieldsMap != null) {
            for(Map.Entry<String, Object> entry : fieldsMap.entrySet()){
                fields.getField().add(createField(entry.getKey(), entry.getValue(), isMemoType(entry.getKey())));
            }
        }

        return fields;
    }

    private boolean isMemoType(String fieldName) {
        for (Fields.Field field: editableFieldsList) {
            if (field.getName().equals(fieldName)) {
                return "Memo".equals(field.getType());
            }
        }
        return false;
    }

    private Entity.Fields.Field createField(String name, Object values, boolean isMemoType) {
        Entity.Fields.Field field = new Entity.Fields.Field();
        field.setName(name);

        if (values instanceof ArrayList) {
            for (Object value : (ArrayList) values) {
                field.getValue().add(String.valueOf(value));
            }
        } else {
            String valueStr = isMemoType ? createMemoValue(String.valueOf(values)) : String.valueOf(values);
            field.getValue().add(valueStr);
        }

        return field;
    }

    private String createMemoValue(String plainText) {
        StringBuilder stringBuilder = new StringBuilder();
        stringBuilder.append("<html>\n" +
                " <body>\n");

        if (plainText != null) {
            String[] lines = plainText.split("\n");
            for (String line: lines) {
                stringBuilder
                        .append("<div align=\"left\"><font face=\"Arial\"><span style=\"font-size:8pt\">")
                        .append(line)
                        .append("</span></font></div>");
            }
        }

        stringBuilder.append("</body>\n" +
                " </html>");
        return stringBuilder.toString();
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

    @Nonnull
    @Override
    public List<String> getProductNames() {
        log.info("Trying to get information from HP QC");
        String xmlResult = HPQCUtils.getAllProjects(getHPQCUrl(), username, password);
        List<String> result = parseXml(xmlResult);

        if (result.isEmpty()) {
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

    @Nonnull
    private List<String> parseXml(String xmlResult) {
        Domains domains = HPQCUtils.marshalWithExceptionClass(Domains.class, xmlResult);
        if (domains != null ) {
            List<String> returnList = list();
            for (Domains.Domain domain : domains.getDomains()) {
                if (domain != null) {
                    for (Domains.Domain.Projects.Project project : domain.getProjects().getProject()) {
                        if (project != null) {

                            log.info("Adding domain " + domain.getName() + " and project " + project.getProjectName());

                            returnList.add(domain.getName() + "/" + project.getProjectName());
                        }
                    }
                }
            }

            return returnList;
        }
        return list();
    }

    @Override
    public String getProjectIdByName() {

        return projectName;
    }

    @Override
    public ProjectMetadata getProjectMetadata() {
        editableFieldsList = HPQCUtils.getEditableFields(getHPQCUrl(),username,password,projectName);

        defectListMap =  HPQCUtils.getListValues(getHPQCUrl(),username,password,projectName);

        List<DynamicFormField> dynamicFormFields = convertToGenericField();
        return new ProjectMetadata(dynamicFormFields);
    }

    private List<DynamicFormField> convertToGenericField() {
        if (editableFieldsList == null)
            return null;
        List<DynamicFormField> dynamicFormFields = list();
        for (Fields.Field hpqcField : editableFieldsList) {
            DynamicFormField genericField = new DynamicFormField();
            genericField.setActive(hpqcField.isActive());
            genericField.setEditable(hpqcField.isEditable());
            genericField.setLabel(hpqcField.getLabel());
            genericField.setMaxLength(hpqcField.getSize());
            genericField.setName(hpqcField.getName());
            genericField.setRequired(hpqcField.isRequired());
            genericField.setSupportsMultivalue(hpqcField.isSupportsMultivalue());
            genericField.setOptionsMap(getFieldOptions(hpqcField));
            genericField.setType(hpqcField.getType());

            genericField.setError("required", "This field cannot be empty.");
            genericField.setError("maxlength", "Input up to " + hpqcField.getSize() +" characters only.");

            dynamicFormFields.add(genericField);
        }

        return dynamicFormFields;
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

    private Map<String, String> getFieldOptions(@Nonnull Fields.Field field) {

        Map<String, String> optionMap = new HashMap<>();

        if (field.getType().equals("UsersList")) {

            List<Users.User> users = HPQCUtils.getActiveUsers(getHPQCUrl(),username,password,projectName);
            if (users != null) {
                for (Users.User user : users) {
                    optionMap.put(user.getName(), user.getName());
                }
            }
        } else if (field.getType().equals("LookupList")) {

            List<String> values = defectListMap.get(field.getListId());
            if (values != null)
                for (String value: values) {
                    optionMap.put(value, value);
                }

        } else if (field.getType().equals("Reference") || "subject".equals(field.getName())) {
            Fields.Field.References references = field.getReferences();

            String targetEntity = null;
            if (references != null && references.getRelationReferences() != null && references.getRelationReferences().size() > 0) {
                Fields.Field.RelationReference reference = references.getRelationReferences().get(0);
                targetEntity = reference.getReferencedEntityType();
            } else if ("subject".equals(field.getName())) {
                //This fixing is temporary for Subject field
                targetEntity = "test-folder";
                field.setType("LookupList");

            }
            if (targetEntity != null) {
                Entities entities = HPQCUtils.getEntities(getHPQCUrl(), username, password, projectName, targetEntity);
                if (entities != null) {
                    List<Entity> entityList = entities.getEntities();
                    if (entityList != null) {
                        for (Entity entity : entityList) {
                            Entity.Fields fields = entity.getFields();
                            Entity.Fields.Field idField = fields.findField("id");
                            Entity.Fields.Field nameField = fields.findField("name");
                            if (idField != null && idField.getValue() != null && idField.getValue().size() > 0
                                    && nameField != null && nameField.getValue() != null && nameField.getValue().size() > 0) {
                                optionMap.put(idField.getValue().get(0), idField.getValue().get(0) + " " + nameField.getValue().get(0));
                            }
                        }
                    }
                }

            }

        }
        return optionMap;
    }

}
