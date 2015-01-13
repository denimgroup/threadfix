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
package com.denimgroup.threadfix.viewmodel;

import javax.annotation.Nullable;
import java.util.List;

public class ProjectMetadata {

	private List<String> components;
	private List<String> versions;
	private List<String> severities;
	private List<String> statuses;
	private List<String> priorities;
    private List<DynamicFormField> editableFields;

	public ProjectMetadata(List<String> components, List<String> versions, 
			List<String> severities, List<String> statuses, List<String> priorities) {
		this.components = components;
		this.versions = versions;
		this.severities = severities;
		this.statuses = statuses;
		this.priorities = priorities;
	}

    public ProjectMetadata(List<DynamicFormField> editableFields) {
        this.editableFields = editableFields;
    }


	public List<String> getComponents() {
		return components;
	}

	public void setComponents(List<String> components) {
		this.components = components;
	}

	public List<String> getVersions() {
		return versions;
	}

	public void setVersions(List<String> versions) {
		this.versions = versions;
	}

	public List<String> getSeverities() {
		return severities;
	}

	public void setSeverities(List<String> severities) {
		this.severities = severities;
	}
	
	public List<String> getStatuses() {
		return statuses;
	}

	public void setStatuses(List<String> statuses) {
		this.statuses = statuses;
	}
	
	public List<String> getPriorities() {
		return priorities;
	}

	public void setPriorities(List<String> priorities) {
		this.priorities = priorities;
	}

    @Nullable
    public List<DynamicFormField> getEditableFields() {
        return editableFields;
    }

    public void setEditableFields(List<DynamicFormField> editableFields) {
        this.editableFields = editableFields;
    }
}
