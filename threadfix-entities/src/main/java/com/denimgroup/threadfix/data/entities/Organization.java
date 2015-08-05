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
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonView;
import org.hibernate.annotations.Index;
import org.hibernate.validator.constraints.NotEmpty;

import javax.persistence.*;
import javax.validation.constraints.Size;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.List;

import static com.denimgroup.threadfix.CollectionUtils.list;
import static java.util.Collections.*;

@Entity
@Table(name = "Organization")
@org.hibernate.annotations.Table(appliesTo = "Organization",
        indexes = {
                @Index(name = "activeIndex",
                        columnNames = { "id", "active" }
                )
        }
)
public class Organization extends AuditableEntity {

    // These are used for caching and will require frequent updates.
    private Integer infoVulnCount = 0, lowVulnCount = 0, mediumVulnCount = 0,
            highVulnCount = 0, criticalVulnCount = 0, totalVulnCount = 0;

	private static final long serialVersionUID = 6734388139007659988L;
	
	private List<Application> activeApps;
	private List<AccessControlTeamMap> accessControlTeamMaps;
    private List<Event> events;

	public static final int NAME_LENGTH = 60;

	@NotEmpty(message = "{errors.required}")
	@Size(max = NAME_LENGTH, message = "{errors.maxlength} " + NAME_LENGTH + ".")
	private String name;

	private List<Application> applications;
	private List<SurveyResult> surveyResults;

	@Column(length = NAME_LENGTH, nullable = false)
    @JsonView(Object.class) // This means it will be included in all ObjectWriters with Views.
    public String getName() {
		return name;
	}

	public void setName(String name) {
		this.name = name;
	}

	@OneToMany(mappedBy = "organization")
	@OrderBy("name")
    @JsonIgnore
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

    @OneToMany(mappedBy = "organization", cascade = CascadeType.ALL)
    @JsonIgnore
    public List<AccessControlTeamMap> getAccessControlTeamMaps() {
        return accessControlTeamMaps;
    }

    @Transient
    @JsonView({AllViews.TableRow.class, AllViews.GRCToolsPage.class, AllViews.RestViewTeam2_1.class, AllViews.VulnSearchApplications.class })
    @JsonProperty("applications")
    public List<Application> getActiveApplications() {
        if (activeApps == null && this.applications != null) {
            activeApps = new ArrayList<Application>();
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

	public void setAccessControlTeamMaps(List<AccessControlTeamMap> accessControlTeamMaps) {
		this.accessControlTeamMaps = accessControlTeamMaps;
	}

    @Transient
    @JsonView({Object.class})
    public List<Event> getOrganizationEvents() {
        List<Event> organizationEvents = list();
        for (Application application: getApplications()) {
            for (Event event: application.getEvents()) {
                if (event.getEventActionEnum().isOrganizationEventAction()) {
                    organizationEvents.add(event);
                }
            }
        }
        sort(organizationEvents, new Comparator<Event>() {
            @Override
            public int compare(Event o1, Event o2) {
                if ((o1 == null) && (o2 == null)) {
                    return 0;
                } else if (o1 == null) {
                    return -1;
                } else if (o2 == null) {
                    return 1;
                } else if ((o1.getDate() == null) && (o2.getDate() == null)) {
                    return o1.getId().compareTo(o2.getId());
                } else if (o1.getDate() == null) {
                    return -1;
                } else if (o2.getDate() == null) {
                    return 1;
                } else {
                    return o1.getDate().compareTo(o2.getDate());
                }
            }
        });
        return organizationEvents;
    }

    // TODO this might belong somewhere else
	/*
	 * Index Severity 0 Info 1 Low 2 Medium 3 High 4 Critical 5 # Total vulns
	 */
	public void updateVulnerabilityReport() {

        int info = 0, low = 0, medium = 0, high = 0, critical = 0, total = 0;

		for (Application app : this.applications) {
			if (app != null && app.isActive()) {
                info += app.getInfoVulnCount();
                low += app.getLowVulnCount();
                medium += app.getMediumVulnCount();
                high += app.getHighVulnCount();
                critical += app.getCriticalVulnCount();
                total += app.getTotalVulnCount();
            }
		}

        setInfoVulnCount(info);
        setLowVulnCount(low);
        setMediumVulnCount(medium);
        setHighVulnCount(high);
        setCriticalVulnCount(critical);
        setTotalVulnCount(total);
	}

    @Column
    @JsonView({ AllViews.RestViewTeam2_1.class, AllViews.TableRow.class, AllViews.ApplicationIndexView.class })
    public Integer getTotalVulnCount() {
        return totalVulnCount;
    }

    public void setTotalVulnCount(Integer totalVulnCount) {
        this.totalVulnCount = totalVulnCount;
    }

    @Column
    @JsonView({ AllViews.RestViewTeam2_1.class, AllViews.TableRow.class, AllViews.ApplicationIndexView.class })
    public Integer getInfoVulnCount() {
        return infoVulnCount;
    }

    @Column
    @JsonView({ AllViews.RestViewTeam2_1.class, AllViews.TableRow.class, AllViews.ApplicationIndexView.class })
    public void setInfoVulnCount(Integer infoVulnCount) {
        this.infoVulnCount = infoVulnCount;
    }

    public Integer getLowVulnCount() {
        return lowVulnCount;
    }

    @Column
    @JsonView({ AllViews.RestViewTeam2_1.class, AllViews.TableRow.class, AllViews.ApplicationIndexView.class })
    public void setLowVulnCount(Integer lowVulnCount) {
        this.lowVulnCount = lowVulnCount;
    }

    public Integer getMediumVulnCount() {
        return mediumVulnCount;
    }

    @Column
    @JsonView({ AllViews.RestViewTeam2_1.class, AllViews.TableRow.class, AllViews.ApplicationIndexView.class })
    public void setMediumVulnCount(Integer mediumVulnCount) {
        this.mediumVulnCount = mediumVulnCount;
    }

    public Integer getHighVulnCount() {
        return highVulnCount;
    }

    @Column
    @JsonView({ AllViews.RestViewTeam2_1.class, AllViews.TableRow.class, AllViews.ApplicationIndexView.class })
    public void setHighVulnCount(Integer highVulnCount) {
        this.highVulnCount = highVulnCount;
    }

    @Column
    @JsonView({ AllViews.RestViewTeam2_1.class, AllViews.TableRow.class, AllViews.ApplicationIndexView.class })
    public Integer getCriticalVulnCount() {
        return criticalVulnCount;
    }

    public void setCriticalVulnCount(Integer criticalVulnCount) {
        this.criticalVulnCount = criticalVulnCount;
    }

    @Transient
    @JsonView({ AllViews.ApplicationIndexView.class })
    public Integer getNumApps(){
        List<Application> activeApps = getActiveApplications();
        return (activeApps == null) ? 0 : activeApps.size();
    }

}
