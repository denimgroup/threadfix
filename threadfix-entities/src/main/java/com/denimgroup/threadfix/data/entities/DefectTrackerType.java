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
package com.denimgroup.threadfix.data.entities;

import com.denimgroup.threadfix.CollectionUtils;
import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonView;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.OneToMany;
import javax.persistence.Table;
import java.util.List;
import java.util.Map;

@Entity
@Table(name = "DefectTrackerType")
public class DefectTrackerType extends BaseEntity {

	private static final long serialVersionUID = 1135227457979044959L;

	public static final String BUGZILLA = "Bugzilla";
	public static final String JIRA = "JIRA";
	public static final String MICROSOFT_TFS = "Microsoft TFS";
    public static final String HP_QUALITYCENTER = "HP Quality Center";
    public static final String VERSION_ONE = "Version One";
	public static final Map<String, String> DT_URL_PLACEHOLDER_MAP = CollectionUtils.map(
			BUGZILLA, "http://your.bugzilla.url",
			JIRA, "https://yourproject.atlassian.net",
			MICROSOFT_TFS, "http://tfs-server:8080/tfs",
			HP_QUALITYCENTER, "http://host/qcbin",
			VERSION_ONE, "https://www1.v1host.com/YourOrganization");

	private String name;
	private String version;
	private String fullClassName;
	private String urlPlaceholder;

	private List<DefectTracker> defectTrackerList;

	@Column(length = 25, nullable = false)
    @JsonView(Object.class) // This means it will be included in all ObjectWriters with Views.
	public String getName() {
		return name;
	}

	public void setName(String name) {
		this.name = name;
	}

	@Column(length = 255)
	public String getVersion() {
		return version;
	}

	public void setVersion(String version) {
		this.version = version;
	}

	@OneToMany(mappedBy = "defectTrackerType")
	@JsonIgnore
	public List<DefectTracker> getDefectTrackerList() {
		return defectTrackerList;
	}

	public void setDefectTrackerList(List<DefectTracker> defectTrackerList) {
		this.defectTrackerList = defectTrackerList;
	}

	@Column(length=512)
	public String getFullClassName() {
		return fullClassName;
	}

	public void setFullClassName(String fullClassName) {
		this.fullClassName = fullClassName;
	}

	@Column(length = 255)
	@JsonView(Object.class)
	public String getUrlPlaceholder() {
		return urlPlaceholder;
	}

	public void setUrlPlaceholder(String urlPlaceholder) {
		this.urlPlaceholder = urlPlaceholder;
	}
}
