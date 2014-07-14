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
package com.denimgroup.threadfix.service.defects.utils.jira;

import com.denimgroup.threadfix.exception.RestIOException;
import com.denimgroup.threadfix.logging.SanitizedLogger;
import com.denimgroup.threadfix.service.defects.utils.DynamicFormField;
import org.codehaus.jackson.map.ObjectMapper;

import java.io.IOException;
import java.util.List;
import java.util.Map;

import static com.denimgroup.threadfix.CollectionUtils.list;
import static com.denimgroup.threadfix.service.defects.utils.jira.JiraJsonMetadataResponse.Field;
import static com.denimgroup.threadfix.service.defects.utils.jira.JiraJsonMetadataResponse.IssueType;
import static com.denimgroup.threadfix.service.defects.utils.jira.JiraJsonMetadataResponse.Project;

/**
 * Created by mac on 7/11/14.
 */
public class DynamicFormFieldParser {

    private DynamicFormFieldParser() {}

    private static final SanitizedLogger LOG = new SanitizedLogger(DynamicFormFieldParser.class);

    public static Project getJiraProjectMetadata(String jsonString) {
        try {
            return new ObjectMapper().readValue(jsonString, JiraJsonMetadataResponse.class).getProjectOrNull();
        } catch (IOException e) {
            LOG.info("Failed to deserialize JSON.");
            LOG.debug("Failing JSON: " + jsonString, e);

            throw new RestIOException(e, "Unable to parse server response.");
        }
    }

    public static List<DynamicFormField> getFields(String jsonString, FieldRetriever retriever) {

        LOG.info("Starting JSON field description deserialization.");

        try {
            JiraJsonMetadataResponse response =
                    new ObjectMapper().readValue(jsonString, JiraJsonMetadataResponse.class);

            assert response.projects.size() != 0 :
                    "The response didn't contain any projects. Something went wrong.";
            assert response.projects.size() == 1 :
                    "The response contained more than one project. Something went wrong.";

            Project project = response.getProjectOrNull();

            List<DynamicFormField> fieldList = list();

            if (project != null) {
                for (IssueType issueType : project.getIssuetypes()) {
                    for (Map.Entry<String, Field> entry : issueType.getFields().entrySet()) {
                        Field jsonField = entry.getValue();
                        String type = jsonField.getSchema().getType();

                        if ("array".equals(type) && "attachment".equals(jsonField.getSchema().getItems())) {
                            continue; // you can't make attachments required and we don't support uploads.
                        }

                        DynamicFormField field = new DynamicFormField();

                        field.setRequired(jsonField.isRequired());
                        field.setName(entry.getKey());
                        field.setLabel(jsonField.getName());
                        field.setActive(true);
                        field.setEditable(true);

                        if (type.equals("timetracking")) {
                            DynamicFormField originalEstimate = new DynamicFormField();

                            originalEstimate.setRequired(jsonField.isRequired());
                            originalEstimate.setName("timetracking_originalestimate");
                            originalEstimate.setLabel("Original Estimate");
                            originalEstimate.setActive(true);
                            originalEstimate.setEditable(true);
                            originalEstimate.setType("text");
                            fieldList.add(originalEstimate);

                            DynamicFormField remainingEstimate = new DynamicFormField();

                            remainingEstimate.setRequired(jsonField.isRequired());
                            remainingEstimate.setName("timetracking_remainingestimate");
                            remainingEstimate.setLabel("Remaining Estimate");
                            remainingEstimate.setActive(true);
                            remainingEstimate.setEditable(true);
                            remainingEstimate.setType("text");
                            fieldList.add(remainingEstimate);
                            continue;
                        } else if (type.equals("string")) {
                            field.setType("text");
                        } else if (type.equals("date")) {
                            field.setType("date");
                        } else if (jsonField.getAllowedValues() != null && !jsonField.getAllowedValues().isEmpty()) {
                            field.setType("select");
                            field.setOptionsMap(jsonField.getOptionsMap());
                        } else if (type.equals("array") && jsonField.getSchema().getItems().equals("string")) {
                            field.setType("text");
                            field.setSupportsMultivalue(true);

                        } else if (type.equals("user")) {
                            field.setType("select");
                            field.setOptionsMap(retriever.getOptions("user/search?username="));

                        } else if (type.equals("array")) {
                            LOG.error("Unable to determine dynamic type for " + entry.getKey() + ":" + type + " of " +
                                    jsonField.getSchema().getItems());

                            field.setType("select");
                            //field.setOptionsMap(retriever.getOptions(jsonField.getSchema().getItems()));

                            System.out.println(jsonField.getAutoCompleteUrl());
                        }

                        fieldList.add(field);
                    }
                }
            }

            return fieldList;

        } catch (IOException e) {
            LOG.info("Failed to deserialize JSON.");
            LOG.debug("Failing JSON: " + jsonString, e);

            throw new RestIOException(e, "Unable to parse server response.");
        }
    }


}
