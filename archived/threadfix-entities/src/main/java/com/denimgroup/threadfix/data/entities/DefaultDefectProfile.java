package com.denimgroup.threadfix.data.entities;

import java.util.List;

import javax.persistence.*;

import com.denimgroup.threadfix.views.AllViews;
import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonView;

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
