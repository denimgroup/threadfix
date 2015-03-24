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
package com.denimgroup.threadfix.service.defects.utils.tfs;

import com.denimgroup.threadfix.exception.RestIOException;
import com.denimgroup.threadfix.logging.SanitizedLogger;
import com.denimgroup.threadfix.viewmodel.DynamicFormField;
import com.microsoft.tfs.core.clients.workitem.WorkItem;
import com.microsoft.tfs.core.clients.workitem.fields.Field;
import com.microsoft.tfs.core.clients.workitem.fields.FieldDefinitionCollection;
import com.microsoft.tfs.core.clients.workitem.fields.FieldStatus;
import com.microsoft.tfs.core.clients.workitem.fields.FieldType;
import com.microsoft.tfs.core.clients.workitem.form.WIFormControl;
import com.microsoft.tfs.core.clients.workitem.form.WIFormElement;
import com.microsoft.tfs.core.clients.workitem.form.WIFormLayout;
import com.microsoft.tfs.core.clients.workitem.form.WIFormReadOnlyEnum;
import com.microsoft.tfs.core.clients.workitem.node.Node;
import com.microsoft.tfs.core.clients.workitem.node.NodeCollection;

import java.util.List;
import java.util.Map;

import static com.denimgroup.threadfix.CollectionUtils.list;
import static com.denimgroup.threadfix.CollectionUtils.map;

/**
 * Created by stran on 3/10/15.
 */
public class DynamicFormFieldParser {

    private static final String
            TREEPATH_SEPARATOR = "\\",
            INTERGER_REGEX = "^[0-9]*$";
    public static final String WORKITEM_TYPE = "workItemType";

    private DynamicFormFieldParser() {
    }

    private static final SanitizedLogger LOG = new SanitizedLogger(DynamicFormFieldParser.class);

    public static List<DynamicFormField> getFields(WorkItem item, Map<String, String> wiTypeValuesMap) {

        LOG.debug("Starting to get dynamic forms from TFS API.");
        List<DynamicFormField> fieldList = list();

        try {

            WIFormLayout[] layouts = item.getType().getFormDescription().getLayoutChildren();

            // If at least one WorkItem Form Layout is found, then add this WorkItem Type to ThreadFix dynamic form
            if (layouts != null && layouts.length > 0) {
                String workItemName = item.getType().getName();
                wiTypeValuesMap.put(String.valueOf(item.getType().getID()), workItemName);

                // Choose the first layout to display in ThreadFix
                WIFormLayout layout = layouts[0];
                for (WIFormElement element: layout.getChildElements()) {
                    fieldList.addAll(getFieldsFromWIFormElement(item, element));
                }
            }

            return fieldList;

        } catch (Exception e) {
            LOG.error("Failed to create dynamic form from workitem.");

            throw new RestIOException(e, "Unable to parse form layout.");
        }
    }


    private static List<DynamicFormField> getFieldsFromWIFormElement(WorkItem workItem, WIFormElement element) {

        List<DynamicFormField> fieldList = list();

        if (element instanceof WIFormControl) {

            WIFormControl elementCtrl = (WIFormControl) element;
            Field fieldItem;

            if (elementCtrl.getFieldName() != null) {
                fieldItem = workItem.getFields().getField(elementCtrl.getFieldName());

                if (fieldItem != null) {

                    DynamicFormField genericField = new DynamicFormField();
                    genericField.setShow(WORKITEM_TYPE + "=" + workItem.getType().getID());

                    // Adding WorkItem Type name at the end of modal field to discriminate from same modal fields of other WorkItem Types
                    genericField.setName(elementCtrl.getFieldName() + "." + workItem.getType().getID());

                    genericField.setLabel((elementCtrl.getLabel() != null && !elementCtrl.getLabel().isEmpty() ? elementCtrl.getLabel().replace("&", "") : fieldItem.getName()));
                    genericField.setActive(true);

                    if (elementCtrl.getReadOnly() != WIFormReadOnlyEnum.TRUE) {
                        genericField.setEditable(true);
                        if (fieldItem.getAllowedValues() != null && fieldItem.getAllowedValues().size() > 0 || fieldItem.getFieldDefinition().getFieldType() == FieldType.TREEPATH) {
                            genericField.setType("select");

                            Map<String, String> optionMap = map();
                            if (fieldItem.getFieldDefinition().getFieldType() != FieldType.TREEPATH)
                                for (String allowedValue : fieldItem.getAllowedValues())
                                    optionMap.put(allowedValue, allowedValue);
                            else {
                                // If FieldType is TreePath, then calculate option values.
                                // Based on documentation, only 2 fields System.IterationPath and System.AreaPath can be this type
                                NodeCollection nodeCollection = null;
                                if (elementCtrl.getFieldName().equals("System.IterationPath")) {
                                    nodeCollection = workItem.getProject().getIterationRootNodes();
                                } else if (elementCtrl.getFieldName().equals("System.AreaPath")) {
                                    nodeCollection = workItem.getProject().getAreaRootNodes();
                                }
                                optionMap.put(workItem.getProject().getName(), workItem.getProject().getName());
                                createValuesMapForNodeCollection(nodeCollection, optionMap, workItem.getProject().getName());
                            }
                            genericField.setOptionsMap(optionMap);
                        } else {
                            setType(genericField, fieldItem);
                        }

                        genericField.setRequired(determineRequired(fieldItem));

                    } else {
                        genericField.setEditable(false);
                        genericField.setType("string");
                    }

                    genericField.setValue(fieldItem.getValue());
                    fieldList.add(genericField);

                } else {
                    LOG.warn("Not going to display field type: " + elementCtrl.getType());
                }
            }
        } else {
            for (WIFormElement child: element.getChildElements()) {
                fieldList.addAll(getFieldsFromWIFormElement(workItem, child));
            }
        }

        return fieldList;

    }

    /**
     * Check if field is required by set its value to null
     * @param fieldItem
     * @return
     */
    private static boolean determineRequired(Field fieldItem) {
        Object oldValue = fieldItem.getValue();
        fieldItem.setValue(null);
        FieldStatus status = fieldItem.getStatus();
        boolean isRequired = status == FieldStatus.INVALID_EMPTY || status == FieldStatus.INVALID_PATH;
        fieldItem.setValue(oldValue);
        return isRequired;
    }

    private static void createValuesMapForNodeCollection(NodeCollection nodeCollection, Map<String, String> optionMap, String rootNodeName) {
        String nodeStr;
        for (Node node : nodeCollection.getNodes()) {
            nodeStr = rootNodeName + TREEPATH_SEPARATOR + node.getName();
            optionMap.put(nodeStr, nodeStr);
            createValuesMapForNodeCollection(node.getChildNodes(), optionMap, nodeStr);
        }
    }

    private static String getType(FieldType fieldType) {

        if (fieldType == FieldType.HISTORY || fieldType == FieldType.PLAINTEXT || fieldType == FieldType.HTML)
            return "textarea";
        else if (fieldType == FieldType.INTEGER || fieldType == FieldType.DOUBLE)
            return "number";
        else if (fieldType == FieldType.DATETIME)
            return "date";
        else if (fieldType == FieldType.TREEPATH)
            return "select";
        else
            return "string";
    }

    private static void setType(DynamicFormField genericField, Field workItemField) {
        FieldType fieldType = workItemField.getFieldDefinition().getFieldType();
        String type = getType(fieldType);
        genericField.setType(type);

        if ("number".equals(type)) {
            genericField.setStep(fieldType == FieldType.INTEGER ? "1" : "any");
            genericField.setValidate(fieldType == FieldType.DOUBLE ? INTERGER_REGEX : null);
            genericField.setMinValue(0);
            if (fieldType == FieldType.INTEGER)
                genericField.setError("pattern", "Input integer only.");
        }

    }

    /**
     * Filter fields from dynamic form submitted with ended with WorkItemType ID
     * @param fieldsMap
     * @return
     */
    public static Map<String, Object> filterFieldsByWorkItemType(Map<String, Object> fieldsMap) {

        String itemTypeId = fieldsMap.get(WORKITEM_TYPE).toString();

        if (itemTypeId != null) {

            Map<String, Object> filteredMap = map();
            for (String key: fieldsMap.keySet()) {
                if (key.endsWith("." + itemTypeId)) {
                    int ind = key.lastIndexOf("." + itemTypeId);
                    String newKey = new StringBuilder(key).replace(ind, ind + itemTypeId.length()+1,"").toString();
                    filteredMap.put(newKey, fieldsMap.get(key));
                }
            }

            return filteredMap;

        } else return fieldsMap;

    }
}
