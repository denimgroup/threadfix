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

import com.denimgroup.threadfix.views.AllViews;
import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonView;
import org.hibernate.validator.constraints.NotEmpty;
import org.hibernate.validator.constraints.URL;

import javax.persistence.*;
import javax.validation.constraints.Size;
import java.util.List;

@Entity
@Table(name = "DefectTracker")
public class DefectTracker extends AuditableEntity {

	private static final long serialVersionUID = 1135227457979044959L;
	
	public final static int NAME_LENGTH = 50;
	public final static int URL_LENGTH = 255;

	@NotEmpty(message = "{errors.required}")
	@Size(max = NAME_LENGTH, message = "{errors.maxlength} " + NAME_LENGTH + ".")
	private String name;

	@URL(message = "{errors.url}")
	@NotEmpty(message = "{errors.required}")
	@Size(max = URL_LENGTH, message = "{errors.maxlength} " + URL_LENGTH + ".")
	private String url;

	private DefectTrackerType defectTrackerType;
	private List<Application> applications;
	private List<DefaultDefectProfile> defaultDefectProfiles;

	@Column(length = NAME_LENGTH)
    @JsonView(Object.class) // This means it will be included in all ObjectWriters with Views.
	public String getName() {
		return name;
	}

	public void setName(String name) {
		this.name = name;
	}

	@Column(length = URL_LENGTH)
    @JsonView(Object.class)
	public String getUrl() {
		return url;
	}

	public void setUrl(String url) {
		this.url = url;
	}

	@ManyToOne
	@JoinColumn(name = "defectTrackerTypeId")
    @JsonView(Object.class)
    public DefectTrackerType getDefectTrackerType() {
		return defectTrackerType;
	}

	public void setDefectTrackerType(DefectTrackerType defectTrackerType) {
		this.defectTrackerType = defectTrackerType;
	}

	@OneToMany
	@JoinColumn(name = "defectTrackerId")
	@JsonView(AllViews.DefectTrackerInfos.class)
	public List<Application> getApplications() {
		return applications;
	}

	public void setApplications(List<Application> applications) {
		this.applications = applications;
	}

	@JsonView(AllViews.DefectTrackerInfos.class)
	@OneToMany(mappedBy = "defectTracker", cascade = CascadeType.ALL)
	public List<DefaultDefectProfile> getDefaultDefectProfiles() {
		return defaultDefectProfiles;
	}

	public void setDefaultDefectProfiles(List<DefaultDefectProfile> defaultDefectProfiles) {
		this.defaultDefectProfiles = defaultDefectProfiles;
	}

	@Transient
	@JsonIgnore
	public String getDisplayName() {
		return this.toString();
	}

	@Override
	@Transient
	public String toString() {
		String displayName = name;
		if (defectTrackerType != null) {
			displayName += " (" + defectTrackerType.getName() + ")";
		}
		return displayName;
	}
	
}
