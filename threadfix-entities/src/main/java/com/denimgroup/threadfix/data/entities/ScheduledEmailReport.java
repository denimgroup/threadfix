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
import com.fasterxml.jackson.annotation.JsonView;
import org.hibernate.annotations.CollectionOfElements;

import javax.persistence.*;
import java.util.List;

@Entity
@Table(name="ScheduledEmailReport")
public class ScheduledEmailReport extends ScheduledJob {

	private static final long serialVersionUID = 2972698237771512123L;

	private GenericSeverity severityLevel;
    private List<EmailList> emailLists;
	private List<String> emailAddresses;
	private List<Organization> organizations;

	@CollectionOfElements
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
    @JsonView(AllViews.ScheduledEmailReportView.class)
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
    @JsonView(AllViews.ScheduledEmailReportView.class)
	public List<Organization> getOrganizations() {
		return organizations;
	}

	public void setOrganizations(List<Organization> organizations) {
		this.organizations = organizations;
	}
}
