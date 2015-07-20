package com.denimgroup.threadfix.data.entities;

import java.io.Serializable;
import java.util.List;
import java.util.Map;

import javax.persistence.*;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonView;

import static com.denimgroup.threadfix.CollectionUtils.map;

@Entity
@Table(name="ScheduledEmailReport")
public class ScheduledEmailReport extends ScheduledJob {

	private static final long serialVersionUID = 2972698237771512123L;

	private GenericSeverity severityLevel;
    private List<EmailList> emailLists;
	private List<String> emailAddresses;
	private List<Organization> organizations;

	@ElementCollection
	@Column(name = "emailAddress", length = 128)
	@CollectionTable(name = "ReportEmailAddress", joinColumns = @JoinColumn(name = "ScheduledEmailReportId"))
	@JsonView(Object.class)
	public List<String> getEmailAddresses() {
		return emailAddresses;
	}

	public void setEmailAddresses(List<String> emailAddresses) {
		this.emailAddresses = emailAddresses;
	}

    @ManyToMany
    @JoinTable(name="ScheduledEmailReport_EmailList",
            joinColumns={@JoinColumn(name="scheduledEmailReportId")},
            inverseJoinColumns={@JoinColumn(name="emailListId")})
    public List<EmailList> getEmailLists() {
        return emailLists;
    }

    public void setEmailLists(List<EmailList> emailLists) {
        this.emailLists = emailLists;
    }

    @ManyToOne
	@JoinColumn(name = "severityLevelId")
	@JsonView(Object.class)
	public GenericSeverity getSeverityLevel() {
		return severityLevel;
	}

	public void setSeverityLevel(GenericSeverity severityLevel) {
		this.severityLevel = severityLevel;
	}

    @ManyToMany
    @JoinTable(name="ScheduledEmailReport_Organization",
            joinColumns={@JoinColumn(name="scheduledEmailReportId")},
            inverseJoinColumns={@JoinColumn(name="organizationId")})
    @JsonView(Object.class)
	public List<Organization> getOrganizations() {
		return organizations;
	}

	public void setOrganizations(List<Organization> organizations) {
		this.organizations = organizations;
	}
}
