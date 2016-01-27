////////////////////////////////////////////////////////////////////////
//
//     Copyright (c) 2009-2016 Denim Group, Ltd.
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
package com.denimgroup.threadfix.service.defects.utils.jira;

import com.denimgroup.threadfix.exception.IllegalStateRestException;
import com.denimgroup.threadfix.exception.RestIOException;
import com.denimgroup.threadfix.logging.SanitizedLogger;
import com.denimgroup.threadfix.viewmodels.DynamicFormField;
import org.codehaus.jackson.map.DeserializationConfig;
import org.codehaus.jackson.map.ObjectMapper;

import java.io.IOException;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static com.denimgroup.threadfix.CollectionUtils.list;
import static com.denimgroup.threadfix.CollectionUtils.map;
import static com.denimgroup.threadfix.CollectionUtils.set;
import static com.denimgroup.threadfix.service.defects.utils.jira.JiraCustomFieldsConstants.*;
import static com.denimgroup.threadfix.service.defects.utils.jira.JiraJsonMetadataResponse.*;

/**
 * Created by mac on 7/11/14.
 */
public class DynamicFormFieldParser {

    private static final String
            TIMETRACKING_REGEX = "^([0-9]+[ymwdh] ?)+$",
            PLACEHOLDER_TEXT = "Ex. 7w 2d 6h",
            TIMETRACKING_ERROR = "Invalid format. " + PLACEHOLDER_TEXT,
            FLOAT_REGEX = "^-?[0-9]+(?:\\.[0-9]+)?$";

    private DynamicFormFieldParser() {
    }

    private static ObjectMapper getLenientObjectMapper() {
        ObjectMapper objectMapper = new ObjectMapper();
        objectMapper.configure(DeserializationConfig.Feature.FAIL_ON_UNKNOWN_PROPERTIES, false);
        return objectMapper;
    }

    private static final SanitizedLogger LOG = new SanitizedLogger(DynamicFormFieldParser.class);

    public static Project getJiraProjectMetadata(String jsonString) {
        try {
            return getLenientObjectMapper().readValue(jsonString, JiraJsonMetadataResponse.class).getProjectOrNull();
        } catch (IOException e) {
            LOG.info("Failed to deserialize JSON.");
            LOG.debug("Failing JSON: " + jsonString, e);

            throw new RestIOException(e, "Unable to parse server response.");
        }
    }

    public static List<DynamicFormField> getFields(String jsonString, UserRetriever retriever) {

        LOG.debug("Starting JSON field description deserialization.");

        try {
            ObjectMapper objectMapper = getLenientObjectMapper();

            JiraJsonMetadataResponse response =
                    objectMapper.readValue(jsonString, JiraJsonMetadataResponse.class);

            if (response.projects.size() == 0) {
                throw new IllegalStateRestException("No projects were found. " +
                        "Bad permissions can cause this error. Please check your configuration.");
            }

            assert response.projects.size() == 1 :
                    "The response contained more than one project. Something went wrong.";

            Project project = response.getProjectOrNull();

            List<DynamicFormField> fieldList = list();

            if (project != null) {

                DynamicFormField issueTypeField = new DynamicFormField();
                issueTypeField.setRequired(true);
                issueTypeField.setName("issuetype");
                issueTypeField.setLabel("Issue Type");
                issueTypeField.setActive(true);
                issueTypeField.setEditable(true);
                issueTypeField.setType("select");
                Map<String, String> issueTypeValuesMap = map();
                addField(issueTypeField, fieldList, null);

                Set<String> timetrackingSet = set();

                for (IssueType issueType : project.getIssuetypes()) {
                    issueTypeValuesMap.put(issueType.getId(), issueType.getName());
                    for (Map.Entry<String, Field> entry : issueType.getFields().entrySet()) {
                        Field jsonField = entry.getValue();
                        String type = jsonField.getSchema().getType();

                        if ("issuelink".equals(type))
                            type = "string";

                        if ("array".equals(type) && "attachment".equals(jsonField.getSchema().getItems())) {
                            continue; // you can't make attachments required and we don't support uploads.
                        }

                        DynamicFormField field = new DynamicFormField();

                        field.setShow("issuetype=" + issueType.getId());

                        field.setRequired(jsonField.isRequired());

                        field.setName(entry.getKey());
                        field.setLabel(jsonField.getName());
                        field.setActive(true);
                        field.setEditable(true);

                        if (jsonField.getAllowedValues() != null && !jsonField.getAllowedValues().isEmpty()) {

                            if (MULTISELECT.equals(jsonField.getSchema().getCustom())) {
                                field.setSupportsMultivalue(true);
                            }
                            if (MULTI_CHECKBOX.equals(jsonField.getSchema().getCustom())) {
                                field.setSupportsMultivalue(true);
                                field.setType("checklist");
                            } else if (CASCADING_SELECT.equals(jsonField.getSchema().getCustom())) {
                                field.setType("select");
                            } else {
                                field.setType("select");
                            }

                            field.setOptionsMap(jsonField.getOptionsMap());
                        } else if (type.equals("timetracking")) {
                            LOG.debug("Adding timetracking fields (x2)");

                            if (timetrackingSet.contains(entry.getKey())) {
                                continue; // otherwise we will have duplicates
                            } else {
                                timetrackingSet.add(entry.getKey());
                            }

                            DynamicFormField originalEstimate = new DynamicFormField();

                            originalEstimate.setRequired(jsonField.isRequired());
                            originalEstimate.setName("timetracking_originalestimate");
                            originalEstimate.setLabel("Original Estimate");
                            originalEstimate.setActive(true);
                            originalEstimate.setEditable(true);
                            originalEstimate.setValidate(TIMETRACKING_REGEX);
                            originalEstimate.setType("text");
                            originalEstimate.setPlaceholder(PLACEHOLDER_TEXT);
                            originalEstimate.setError("pattern", TIMETRACKING_ERROR);
                            fieldList.add(originalEstimate);

                            DynamicFormField remainingEstimate = new DynamicFormField();

                            remainingEstimate.setRequired(jsonField.isRequired());
                            remainingEstimate.setName("timetracking_remainingestimate");
                            remainingEstimate.setLabel("Remaining Estimate");
                            remainingEstimate.setActive(true);
                            remainingEstimate.setValidate(TIMETRACKING_REGEX);
                            remainingEstimate.setPlaceholder(PLACEHOLDER_TEXT);
                            remainingEstimate.setEditable(true);
                            remainingEstimate.setType("text");
                            remainingEstimate.setError("pattern", TIMETRACKING_ERROR);
                            fieldList.add(remainingEstimate);
                            continue;
                        } else if (type.equals("string")) {

                            if (URL_TYPE.equals(jsonField.getSchema().getCustom())) {
                                field.setType("url");
                            } else if (TEXTAREA_TYPE.equals(jsonField.getSchema().getCustom())) {
                                field.setType("textarea");
                            } else {
                                field.setType("text");
                            }
                        } else if (type.equals("number")) {
                            if (FLOAT_TYPE.equals(jsonField.getSchema().getCustom())) {
                                field.setValidate(FLOAT_REGEX);
                                field.setType("text");
                                field.setError("pattern", "Must be float format (ex. 3.14)");
                            } else {
                                field.setType("number");
                            }

                        } else if (type.equals("date") || type.equals("datetime")) {
                            field.setType("date");
                        } else if (type.equals("array") && jsonField.getSchema().getItems().equals("string")) {
                            field.setType("text");
                            field.setSupportsMultivalue(true);

                        } else if (type.equals("user")) {
                            field.setType("select");
                            Map<String, String> map = retriever.getUserMap();
                            if (map == null) {
                                field.setType("text");
                            } else field.setOptionsMap(map);

                        } else if (type.equals("array")) {
                            if (jsonField.getSchema().getItems().equals("user")) {
                                field.setType("typeahead");
                                field.setTypeaheadAcceptedType("user");
                                field.setTypeaheadField(field.getName());
                            } else {
                                LOG.error("Unable to determine dynamic type for " + entry.getKey() + ":" + type + " of " +
                                        jsonField.getSchema().getItems());

                                field.setType("select");
                            }
                        }

                        LOG.debug("Adding new field with label " + field.getLabel() + " and type " + field.getType());

                        addField(field, fieldList, issueTypeField);
                    }
                }
                issueTypeField.setOptionsMap(issueTypeValuesMap);
            }

            return fieldList;

        } catch (IOException e) {
            LOG.error("Failed to deserialize JSON.");
            LOG.debug("Failing JSON: " + jsonString, e);

            throw new RestIOException(e, "Unable to parse server response.");
        }
    }

    private static void addField(DynamicFormField newField, List<DynamicFormField> toList, DynamicFormField oldField) {
        if (oldField == null || !oldField.getName().equals(newField.getName()))
            toList.add(newField);
    }

}
