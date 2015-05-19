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
package com.denimgroup.threadfix.service.defects.utils.jira;

import com.denimgroup.threadfix.logging.SanitizedLogger;
import org.apache.commons.lang.StringUtils;

import java.util.List;
import java.util.Map;

import static com.denimgroup.threadfix.CollectionUtils.list;
import static com.denimgroup.threadfix.CollectionUtils.map;
import static com.denimgroup.threadfix.service.defects.utils.jira.JiraCustomFieldsConstants.*;
import static com.denimgroup.threadfix.service.defects.utils.jira.JiraJsonMetadataResponse.*;

/**
 * Created by mac on 7/11/14.
 */
public class DefectPayload {

    private static final SanitizedLogger LOG = new SanitizedLogger(DefectPayload.class);

    Map<String, Object> fields = map();

    public DefectPayload(Map<String, Object> objectMap, Project metadata) {

        if (metadata != null && metadata.getIssueTypeOrNull() != null) {

            fields.put("project", new ObjectDescriptor(metadata.getId()));
            fields.put("issuetype", new ObjectDescriptor("1"));

            IssueType issueType = metadata.getIssueTypeOrNull();

            Object remainingEstimate = objectMap.get("timetracking_remainingestimate");
            Object originalEstimate = objectMap.get("timetracking_originalestimate");
            if (remainingEstimate != null &&
                    originalEstimate != null ) {
                fields.put("timetracking",
                        new TimeTracking(originalEstimate, remainingEstimate));
            }

            for (Map.Entry<String, Field> entry : issueType.getFields().entrySet()) {

                if (entry.getKey().startsWith("timetracking") ||
                        "attachment".equals(entry.getValue().getSchema().getItems())) {
                    continue;
                }

                String key = entry.getKey();

                Object returnedObject = getObjectValue(objectMap, key, entry.getValue());

                if (returnedObject instanceof ObjectDescriptor) {
                    String id = ((ObjectDescriptor) returnedObject).getId();

                    if (!"null".equals(id)) {
                        fields.put(key, returnedObject);
                    }

                } else if (returnedObject instanceof NamedObjectDescriptor) {
                    String name = ((NamedObjectDescriptor) returnedObject).getName();

                    if (!"null".equals(name)) {
                        fields.put(key, returnedObject);
                    }

                } else if (returnedObject != null) {
                    fields.put(key, returnedObject);
                }
            }
        }
    }

    private Object getObjectValue(Map<String, Object> objectMap, String key, Field field) {

        String custom = field.getSchema().getCustom();

        Object returnValue = null;

        LOG.debug(key);
        if (objectMap.containsKey(key)) {

            Object value = objectMap.get(key);

            String type = field.getSchema().getType();
            if (type.equals("string") || type.equals("date")) {

                if (RADIO_BUTTONS.equals(custom) || SELECT.equals(custom)) {
                    returnValue = new ObjectDescriptor(value);
                } else {
                    returnValue = value;
                }
            } else if ("datetime".equals(type)) {
                returnValue = value + "T12:00:00.000+0000";
            } else if (type.equals("array")) {
                String items = field.getSchema().getItems();
                if (MULTISELECT.equals(custom)) {
                    returnValue = getObjectsFromMultivalueSelect(value);
                } else if ("labels".equals(field.getSchema().getSystem())) {
                    returnValue = list(StringUtils.split(String.valueOf(value), ' '));
                } else if (MULTI_CHECKBOX.equals(custom)) {
                    returnValue = getObjectsFromMultivalueSelect(value);
                } else if (CASCADING_SELECT.equals(custom)) {
                    returnValue = new CascadingSelect(value);
                } else if ("string".equals(items) || "date".equals(items)) {
                    returnValue = list(value);
                } else {
                    returnValue = list(new ObjectDescriptor(value));
                }
            } else if (type.equals("user")) {
                returnValue = new NamedObjectDescriptor(value);
            } else if (type.equals("number")) {
                returnValue = getFloatOr0(value);
            } else {
                returnValue = new ObjectDescriptor(value);
            }
        }

        return returnValue;
    }

    public Float getFloatOr0(Object input) {
        try {
            return Float.valueOf(String.valueOf(input));
        } catch (NumberFormatException e) {
            LOG.error("Got input " + input + " which could not be parsed as a float.");
            return 0.0F;
        }
    }

    // multivalue comes in as [ "string1", "string2" ] but we need [ { id: "string1" }, { id: "string2" } ]
    private List<Object> getObjectsFromMultivalueSelect(Object oldValue) {
        List<Object> newValue = list();

        if (oldValue instanceof List<?>) {
            for (Object item : (List) oldValue) {
                newValue.add(new ObjectDescriptor(item));
            }
        }

        if (oldValue instanceof Map<?, ?>) {
            for (Object item : ((Map) oldValue).keySet()) {
                newValue.add(new ObjectDescriptor(item));
            }
        }

        return newValue;
    }

    public Map<String, Object> getFields() {
        return fields;
    }

    public void setFields(Map<String, Object> fields) {
        this.fields = fields;
    }

    public static class ObjectDescriptor {
        String id;

        public ObjectDescriptor(Object value) {
            this.id = String.valueOf(value);
        }

        public String getId() {
            return id;
        }

        public void setId(String id) {
            this.id = id;
        }
    }

    public static class NamedObjectDescriptor {
        String name;

        public NamedObjectDescriptor(Object value) {
            this.name = String.valueOf(value);
        }

        public String getName() {
            return name;
        }

        public void setName(String name) {
            this.name = name;
        }
    }

    public static class TimeTracking {
        String remainingEstimate, originalEstimate;

        public TimeTracking(Object timetracking_originalestimate, Object timetracking_remainingestimate) {
            originalEstimate = timetracking_originalestimate.toString();
            remainingEstimate = timetracking_remainingestimate.toString();
        }

        public String getRemainingEstimate() {
            return remainingEstimate;
        }

        public void setRemainingEstimate(String remainingEstimate) {
            this.remainingEstimate = remainingEstimate;
        }

        public String getOriginalEstimate() {
            return originalEstimate;
        }

        public void setOriginalEstimate(String originalEstimate) {
            this.originalEstimate = originalEstimate;
        }
    }

    public static class CascadingSelect {
        String value;
        CascadingSelectChild child;

        public CascadingSelect(Object value) {
            String stringValue = String.valueOf(value);
            String [] splitSelectValues = StringUtils.splitByWholeSeparator(stringValue, CASCADING_SEPARATOR);
            assert splitSelectValues.length == 2 : "Got " + splitSelectValues.length + " results instead of 2.";

            this.value = splitSelectValues[0];
            child = new CascadingSelectChild(splitSelectValues[1]);
        }

        public String getValue() {
            return value;
        }

        public void setValue(String value) {
            this.value = value;
        }

        public CascadingSelectChild getChild() {
            return child;
        }

        public void setChild(CascadingSelectChild child) {
            this.child = child;
        }
    }

    public static class CascadingSelectChild {
        String value;

        public CascadingSelectChild(String value) {
            this.value = value;
        }

        public String getValue() {
            return value;
        }

        public void setValue(String value) {
            this.value = value;
        }
    }

}
