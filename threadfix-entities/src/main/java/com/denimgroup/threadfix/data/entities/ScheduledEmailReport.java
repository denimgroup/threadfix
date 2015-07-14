package com.denimgroup.threadfix.data.entities;

import java.util.List;

import javax.persistence.CollectionTable;
import javax.persistence.Column;
import javax.persistence.ElementCollection;
import javax.persistence.Entity;
import javax.persistence.JoinColumn;
import javax.persistence.JoinTable;
import javax.persistence.ManyToMany;
import javax.persistence.ManyToOne;
import javax.persistence.Table;

import com.fasterxml.jackson.annotation.JsonView;

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
    @JoinColumn(name = "emailListId")
    @JsonView(Object.class)
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
