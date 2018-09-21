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

import java.util.List;
import java.util.Map;

import static com.denimgroup.threadfix.CollectionUtils.map;
import static com.denimgroup.threadfix.service.defects.utils.jira.JiraCustomFieldsConstants.CASCADING_SEPARATOR;

/**
 * Created by mac on 7/11/14.
 */
public class JiraJsonMetadataResponse {

    public List<Project> getProjects() {
        return projects;
    }

    public void setProjects(List<Project> projects) {
        this.projects = projects;
    }

    public String getExpand() {
        return expand;
    }

    public void setExpand(String expand) {
        this.expand = expand;
    }

    String        expand;
    List<Project> projects;

    Project getProjectOrNull() {
        if (projects != null && projects.size() == 1) {
            return projects.get(0);
        } else {
            return null;
        }
    }

    public static class Project {

        public String getExpand() {
            return expand;
        }

        public void setExpand(String expand) {
            this.expand = expand;
        }

        public String getName() {
            return name;
        }

        public void setName(String name) {
            this.name = name;
        }

        public String getKey() {
            return key;
        }

        public void setKey(String key) {
            this.key = key;
        }

        public String getId() {
            return id;
        }

        public void setId(String id) {
            this.id = id;
        }

        public String getSelf() {
            return self;
        }

        public void setSelf(String self) {
            this.self = self;
        }

        public List<IssueType> getIssuetypes() {
            return issuetypes;
        }

        public void setIssuetypes(List<IssueType> issuetypes) {
            this.issuetypes = issuetypes;
        }

        public Map<String, String> getAvatarUrls() {
            return avatarUrls;
        }

        public void setAvatarUrls(Map<String, String> avatarUrls) {
            this.avatarUrls = avatarUrls;
        }

        String name;

        String expand, self, id, key;

        List<IssueType> issuetypes;

        Map<String, String> avatarUrls;

        public IssueType getIssueTypeOrNull() {
            if (issuetypes != null && issuetypes.size() == 1) {
                return issuetypes.get(0);
            } else {
                return null;
            }
        }

    }

    public static class IssueType {

        String iconUrl, expand;
        boolean required, subtask;

        public String getExpand() {
            return expand;
        }

        public void setExpand(String expand) {
            this.expand = expand;
        }

        public boolean isSubtask() {
            return subtask;
        }

        public void setSubtask(boolean subtask) {
            this.subtask = subtask;
        }

        public String getIconUrl() {
            return iconUrl;
        }

        public void setIconUrl(String iconUrl) {
            this.iconUrl = iconUrl;
        }

        public boolean isRequired() {
            return required;
        }

        public void setRequired(boolean required) {
            this.required = required;
        }

        public String getName() {
            return name;
        }

        public void setName(String name) {
            this.name = name;
        }

        public String getSelf() {
            return self;
        }

        public void setSelf(String self) {
            this.self = self;
        }

        public String getId() {
            return id;
        }

        public void setId(String id) {
            this.id = id;
        }

        public String getDescription() {
            return description;
        }

        public void setDescription(String description) {
            this.description = description;
        }

        public Map<String, Field> getFields() {
            return fields;
        }

        public void setFields(Map<String, Field> fields) {
            this.fields = fields;
        }

        String name, self, id, description;

        Map<String, Field> fields;
    }

    public static class Field {

        boolean required;
        String  name, autoCompleteUrl;
        boolean            hasDefaultValue;
        List<String>       operations;
        List<AllowedValue> allowedValues;
        Schema             schema;

        public String getAutoCompleteUrl() {
            return autoCompleteUrl;
        }

        public void setAutoCompleteUrl(String autoCompleteUrl) {
            this.autoCompleteUrl = autoCompleteUrl;
        }

        public boolean isRequired() {
            return required;
        }

        public void setRequired(boolean required) {
            this.required = required;
        }

        public String getName() {
            return name;
        }

        public void setName(String name) {
            this.name = name;
        }

        public boolean isHasDefaultValue() {
            return hasDefaultValue;
        }

        public void setHasDefaultValue(boolean hasDefaultValue) {
            this.hasDefaultValue = hasDefaultValue;
        }

        public List<String> getOperations() {
            return operations;
        }

        public void setOperations(List<String> operations) {
            this.operations = operations;
        }

        public List<AllowedValue> getAllowedValues() {
            return allowedValues;
        }

        public void setAllowedValues(List<AllowedValue> allowedValues) {
            this.allowedValues = allowedValues;
        }

        public Map<String, String> getOptionsMap() {
            Map<String, String> map = map();

            if (allowedValues != null) {
                for (AllowedValue value : allowedValues) {

                    if (value.getChildren() == null || value.getChildren().isEmpty()) {
                        if (value.getName() != null) {
                            map.put(value.getId(), value.getName());
                        } else if (value.getValue() != null) {
                            map.put(value.getId(), value.getValue());
                        }
                    } else {
                        // probably cascading select
                        for (Child child : value.getChildren()) {
                            map.put(value.getValue() + CASCADING_SEPARATOR + child.getValue(),
                                    value.getValue() + " - " + child.getValue());
                        }
                    }
                }
            }

            return map;
        }

        public Schema getSchema() {
            return schema;
        }

        public void setSchema(Schema schema) {
            this.schema = schema;
        }
    }

    public static class Schema {
        String type, system, custom;

        Number customId;

        public String getCustom() {
            return custom;
        }

        public void setCustom(String custom) {
            this.custom = custom;
        }

        public Number getCustomId() {
            return customId;
        }

        public void setCustomId(Number customId) {
            this.customId = customId;
        }

        public String getSystem() {
            return system;
        }

        public void setSystem(String system) {
            this.system = system;
        }

        public String getType() {
            return type;
        }

        public void setType(String type) {
            this.type = type;
        }

        public String getItems() {
            return items;
        }

        public void setItems(String items) {
            this.items = items;
        }

        String items;
    }

    public static class AllowedValue {
        String self, id, description, iconUrl, name, key, userStartDate, userReleaseDate, startDate, releaseDate, value;
        boolean subtask, released, archived, overdue;
        Map<String, String> avatarUrls;
        Number              projectId;
        List<Child>         children;

        public List<Child> getChildren() {
            return children;
        }

        public void setChildren(List<Child> children) {
            this.children = children;
        }

        public String getValue() {
            return value;
        }

        public void setValue(String value) {
            this.value = value;
        }

        public String getReleaseDate() {
            return releaseDate;
        }

        public void setReleaseDate(String releaseDate) {
            this.releaseDate = releaseDate;
        }

        public String getStartDate() {
            return startDate;
        }

        public void setStartDate(String startDate) {
            this.startDate = startDate;
        }

        public String getUserStartDate() {
            return userStartDate;
        }

        public void setUserStartDate(String userStartDate) {
            this.userStartDate = userStartDate;
        }

        public String getUserReleaseDate() {
            return userReleaseDate;
        }

        public void setUserReleaseDate(String userReleaseDate) {
            this.userReleaseDate = userReleaseDate;
        }

        public boolean isReleased() {
            return released;
        }

        public void setReleased(boolean released) {
            this.released = released;
        }

        public boolean isArchived() {
            return archived;
        }

        public void setArchived(boolean archived) {
            this.archived = archived;
        }

        public boolean isOverdue() {
            return overdue;
        }

        public void setOverdue(boolean overdue) {
            this.overdue = overdue;
        }

        public Number getProjectId() {
            return projectId;
        }

        public void setProjectId(Number projectId) {
            this.projectId = projectId;
        }

        public Map<String, String> getAvatarUrls() {
            return avatarUrls;
        }

        public void setAvatarUrls(Map<String, String> avatarUrls) {
            this.avatarUrls = avatarUrls;
        }

        public String getKey() {
            return key;
        }

        public void setKey(String key) {
            this.key = key;
        }

        public String getSelf() {
            return self;
        }

        public void setSelf(String self) {
            this.self = self;
        }

        public String getId() {
            return id;
        }

        public void setId(String id) {
            this.id = id;
        }

        public String getDescription() {
            return description;
        }

        public void setDescription(String description) {
            this.description = description;
        }

        public String getIconUrl() {
            return iconUrl;
        }

        public void setIconUrl(String iconUrl) {
            this.iconUrl = iconUrl;
        }

        public String getName() {
            return name;
        }

        public void setName(String name) {
            this.name = name;
        }

        public boolean isSubtask() {
            return subtask;
        }

        public void setSubtask(boolean subtask) {
            this.subtask = subtask;
        }
    }

    public static class Child {
        String self, value, id;

        public String getSelf() {
            return self;
        }

        public void setSelf(String self) {
            this.self = self;
        }

        public String getValue() {
            return value;
        }

        public void setValue(String value) {
            this.value = value;
        }

        public String getId() {
            return id;
        }

        public void setId(String id) {
            this.id = id;
        }
    }
}