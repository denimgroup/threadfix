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

package com.denimgroup.threadfix.data.entities;

import com.denimgroup.threadfix.views.AllViews;
import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonView;

import javax.persistence.*;
import java.util.List;

@Entity
@Table(name = "DefaultDefectProfile")
public class DefaultDefectProfile extends AuditableEntity {

	private static final long serialVersionUID = -1581568334031972837L;

	private String name;
	private List<DefaultDefectField> defaultDefectFields;
	private DefectTracker defectTracker;
	private Application referenceApplication;
	private List<Application> applicationsWithMainProfile;

	@Column(length = 25, nullable = false)
        @JsonView(Object.class) // This means it will be included in all ObjectWriters with Views.
	public String getName() {
		return name;
	}

	public void setName(String name) {
		this.name = name;
	}

	@Transient
	@JsonView(Object.class) // This means it will be included in all ObjectWriters with Views.
	public String getFullName() {
		if (referenceApplication != null) {
			return referenceApplication.getName() + " / " + name;
		}
		return name;
	}

	@ManyToOne
	@JoinColumn(name = "defectTrackerId")
	@JsonIgnore
        public DefectTracker getDefectTracker() {
		return defectTracker;
	}

	public void setDefectTracker(DefectTracker defectTracker) {
		this.defectTracker = defectTracker;
	}

	@ManyToOne
	@JoinColumn(name = "applicationId")
	@JsonView(AllViews.DefectTrackerInfos.class)
	public Application getReferenceApplication() {
		return referenceApplication;
	}

	public void setReferenceApplication(Application application) {
		this.referenceApplication = application;
	}

	@OneToMany(mappedBy = "defaultDefectProfile", cascade = CascadeType.ALL)
	@JsonIgnore
	public List<DefaultDefectField> getDefaultDefectFields() {
		return defaultDefectFields;
	}

	public void setDefaultDefectFields(List<DefaultDefectField> defaultDefectFields) {
		this.defaultDefectFields = defaultDefectFields;
	}

	@OneToMany(mappedBy = "mainDefaultDefectProfile")
	@JsonIgnore
	public List<Application> getApplicationsWithMainProfile() {
		return applicationsWithMainProfile;
	}

	public void setApplicationsWithMainProfile(
			List<Application> applicationsWithMainProfile) {
		this.applicationsWithMainProfile = applicationsWithMainProfile;
	}
}
