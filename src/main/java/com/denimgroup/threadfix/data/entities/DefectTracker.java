////////////////////////////////////////////////////////////////////////
//
//     Copyright (c) 2009-2011 Denim Group, Ltd.
//
//     The contents of this file are subject to the Mozilla Public License
//     Version 1.1 (the "License"); you may not use this file except in
//     compliance with the License. You may obtain a copy of the License at
//     http://www.mozilla.org/MPL/
//
//     Software distributed under the License is distributed on an "AS IS"
//     basis, WITHOUT WARRANTY OF ANY KIND, either express or implied. See the
//     License for the specific language governing rights and limitations
//     under the License.
//
//     The Original Code is Vulnerability Manager.
//
//     The Initial Developer of the Original Code is Denim Group, Ltd.
//     Portions created by Denim Group, Ltd. are Copyright (C)
//     Denim Group, Ltd. All Rights Reserved.
//
//     Contributor(s): Denim Group, Ltd.
//
////////////////////////////////////////////////////////////////////////
package com.denimgroup.threadfix.data.entities;

import java.util.List;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.JoinColumn;
import javax.persistence.ManyToOne;
import javax.persistence.OneToMany;
import javax.persistence.Table;
import javax.persistence.Transient;
import javax.validation.constraints.Size;

import org.hibernate.validator.constraints.NotEmpty;
import org.hibernate.validator.constraints.URL;

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

	@Column(length = NAME_LENGTH)
	public String getName() {
		return name;
	}

	public void setName(String name) {
		this.name = name;
	}

	@Column(length = URL_LENGTH)
	public String getUrl() {
		return url;
	}

	public void setUrl(String url) {
		this.url = url;
	}

	@ManyToOne
	@JoinColumn(name = "defectTrackerTypeId")
	public DefectTrackerType getDefectTrackerType() {
		return defectTrackerType;
	}

	public void setDefectTrackerType(DefectTrackerType defectTrackerType) {
		this.defectTrackerType = defectTrackerType;
	}

	@OneToMany
	@JoinColumn(name = "defectTrackerId")
	public List<Application> getApplications() {
		return applications;
	}

	public void setApplications(List<Application> applications) {
		this.applications = applications;
	}

	@Transient
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
