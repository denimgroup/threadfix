////////////////////////////////////////////////////////////////////////
//
//     Copyright (c) 2009-2013 Denim Group, Ltd.
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

import java.util.ArrayList;
import java.util.List;

import javax.persistence.CascadeType;
import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.OneToMany;
import javax.persistence.OrderBy;
import javax.persistence.Table;
import javax.persistence.Transient;
import javax.validation.constraints.Size;

import org.codehaus.jackson.annotate.JsonIgnore;
import org.hibernate.validator.constraints.NotEmpty;

@Entity
@Table(name = "Organization")
public class Organization extends AuditableEntity {

	private static final long serialVersionUID = 6734388139007659988L;
	
	private List<Application> activeApps;
	private List<AccessControlTeamMap> accessControlTeamMaps;
	
	public static final int NAME_LENGTH = 60;

	@NotEmpty(message = "{errors.required}")
	@Size(max = NAME_LENGTH, message = "{errors.maxlength} " + NAME_LENGTH + ".")
	private String name;

	private List<Application> applications;
	private List<SurveyResult> surveyResults;

	@Column(length = NAME_LENGTH, nullable = false)
	public String getName() {
		return name;
	}

	public void setName(String name) {
		this.name = name;
	}

	@OneToMany(mappedBy = "organization")
	@OrderBy("name")
	public List<Application> getApplications() {
		return applications;
	}

	public void setApplications(List<Application> applications) {
		this.applications = applications;
	}

	@OneToMany(cascade = { CascadeType.PERSIST, CascadeType.MERGE }, mappedBy = "organization")
	@OrderBy("createdDate DESC")
	@JsonIgnore
	public List<SurveyResult> getSurveyResults() {
		return surveyResults;
	}

	public void setSurveyResults(List<SurveyResult> surveyResults) {
		this.surveyResults = surveyResults;
	}
	
	@Transient
	@JsonIgnore
	public List<Application> getActiveApplications() {
		if (activeApps == null) {
			activeApps = new ArrayList<>();
			for (Application application : this.applications) {
				if (application.isActive())
					activeApps.add(application);
			}
		}
		return activeApps;
	}
	
	// This can be used to set temporary filtered lists of apps for a team
	public void setActiveApplications(List<Application> apps) {
		activeApps = apps;
	}
	
	@OneToMany(mappedBy = "organization", cascade = CascadeType.ALL)
	@JsonIgnore
	public List<AccessControlTeamMap> getAccessControlTeamMaps() {
		return accessControlTeamMaps;
	}

	public void setAccessControlTeamMaps(List<AccessControlTeamMap> accessControlTeamMaps) {
		this.accessControlTeamMaps = accessControlTeamMaps;
	}

	// TODO this might belong somewhere else
	/*
	 * Index Severity 0 Info 1 Low 2 Medium 3 High 4 Critical 5 # Total vulns
	 */
	@Transient
	@JsonIgnore
	public List<Integer> getVulnerabilityReport() {

		int[] calculations = new int[6];
		for (int i = 0; i < calculations.length; i++) {
			calculations[i] = 0;
		}

		for (Application app : this.applications) {
			if (app == null || !app.isActive())
				continue;
			
			for (int i = 0; i < calculations.length; i++) {
				calculations[i] += app.getVulnerabilityReport().get(i);
			}
		}

		List<Integer> retVal = new ArrayList<>();
		for (int i = 0; i < calculations.length; i++) {
			retVal.add(Integer.valueOf(calculations[i]));
		}

		return retVal;
	}

}
