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

import com.denimgroup.threadfix.logging.SanitizedLogger;

import java.util.List;
import java.util.Map;

import static com.denimgroup.threadfix.CollectionUtils.list;
import static com.denimgroup.threadfix.CollectionUtils.newMap;
import static com.denimgroup.threadfix.service.defects.utils.jira.JiraCustomFieldsConstants.*;
import static com.denimgroup.threadfix.service.defects.utils.jira.JiraJsonMetadataResponse.*;

/**
 * Created by mac on 7/11/14.
 */
public class DefectPayload {

    private static final SanitizedLogger LOG = new SanitizedLogger(DefectPayload.class);

    Map<String, Object> fields = newMap();

    public DefectPayload(Map<String, Object> objectMap, Project metadata) {

        if (metadata != null && metadata.getIssueTypeOrNull() != null) {

            fields.put("project", new ObjectDescriptor(metadata.getId()));
            fields.put("issuetype", new ObjectDescriptor("1"));

            IssueType issueType = metadata.getIssueTypeOrNull();

            if (objectMap.containsKey("timetracking_remainingestimate") &&
                    objectMap.containsKey("timetracking_originalestimate")) {
                fields.put("timetracking",
                        new TimeTracking(
                                objectMap.get("timetracking_originalestimate"),
                                objectMap.get("timetracking_remainingestimate")));
            }

            for (Map.Entry<String, Field> entry : issueType.getFields().entrySet()) {

                if (entry.getKey().startsWith("timetracking")) {
                    continue;
                }

                String key = entry.getKey();

                fields.put(key, getObjectValue(objectMap, key, entry.getValue()));
            }
        }
    }

    private Object getObjectValue(Map<String, Object> objectMap, String key, Field value) {

        String custom = value.getSchema().getCustom();

        Object returnValue = null;

        LOG.debug(key);
        if (objectMap.containsKey(key)) {
            String type = value.getSchema().getType();
            if (type.equals("string") || type.equals("date")) {

                if (RADIO_BUTTONS.equals(custom) || SELECT.equals(custom)) {
                    returnValue = new ObjectDescriptor(objectMap.get(key));
                } else {
                    returnValue = objectMap.get(key);
                }
            } else if ("datetime".equals(type)) {
                returnValue = objectMap.get(key) + "T12:00:00.000+0000";
            } else if (type.equals("array")) {
                String items = value.getSchema().getItems();
                if (MULTISELECT.equals(custom)) {

                    Object oldValue = objectMap.get(key);
                    List<Object> newValue = list();
                    if (oldValue instanceof List<?>) {
                        for (Object item : (List) oldValue) {
                            newValue.add(new ObjectDescriptor(item));
                        }
                    }

                    returnValue = newValue; // already a list / multivalue type
                } else if ("string".equals(items) || "date".equals(items)) {
                    returnValue = list(objectMap.get(key));
                } else {
                    returnValue = list(new ObjectDescriptor(objectMap.get(key)));
                }
            } else if (type.equals("user")) {
                returnValue = new NamedObjectDescriptor(objectMap.get(key));
            } else if (type.equals("number")) {
                returnValue = objectMap.get(key);
            } else {
                returnValue = new ObjectDescriptor(objectMap.get(key));
            }
        }

        return returnValue;
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

}
