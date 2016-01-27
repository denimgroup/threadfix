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
import org.hibernate.validator.constraints.NotEmpty;

import javax.persistence.*;
import javax.validation.constraints.Size;
import java.util.List;

import static com.denimgroup.threadfix.CollectionUtils.list;

/**
 * Created by sgerick on 5/26/2015.
 */

@Entity
@Table(name = "Policy")
public class Policy extends AuditableEntity {

    private static final long serialVersionUID = 7188109163348903139L;

    private static final int NAME_LENGTH = 60;
    private static final int EMAIL_LENGTH = 128;

    @NotEmpty(message = "{errors.required}")
    @Size(max = NAME_LENGTH, message = "{errors.maxlength} " + NAME_LENGTH + ".")
    private String name;
    private List<PolicyStatus> policyStatuses;
    private FilterJsonBlob filterJsonBlob;

    private List<EmailList> emailLists;
    @Size(max = EMAIL_LENGTH, message = "{errors.maxlength} " + EMAIL_LENGTH + ".")
    private List<String> emailAddresses;
    private Boolean sendEmail = false;

    @CollectionOfElements // for sonar
    @ElementCollection
    @Column(name = "emailAddress", length = EMAIL_LENGTH)
    @CollectionTable(name = "PolicyEmailAddress", joinColumns = @JoinColumn(name = "PolicyId"))
    @JsonView(AllViews.PolicyPageView.class)
    public List<String> getEmailAddresses() {
        return emailAddresses;
    }

    public void setEmailAddresses(List<String> emailAddresses) {
        this.emailAddresses = emailAddresses;
    }

    @ManyToMany
    @JoinColumn(name = "emailListId")
    @JsonView(AllViews.PolicyPageView.class)
    public List<EmailList> getEmailLists() {
        return emailLists;
    }

    public void setEmailLists(List<EmailList> emailLists) {
        this.emailLists = emailLists;
    }

    @Column(length = NAME_LENGTH, nullable = false)
    @JsonView({AllViews.PolicyPageView.class, AllViews.FormInfo.class})
    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    @OneToMany(mappedBy = "policy", cascade = CascadeType.REMOVE)
    @JsonView(AllViews.PolicyPageView.class)
    public List<PolicyStatus> getPolicyStatuses() {
        return policyStatuses;
    }

    public void setPolicyStatuses(List<PolicyStatus> policyStatuses) {
        this.policyStatuses = policyStatuses;
    }

    @Column
    @JsonView(AllViews.PolicyPageView.class)
    public Boolean isSendEmail() {
        return sendEmail != null && sendEmail;
    }

    public void setSendEmail(Boolean sendEmail) {
        this.sendEmail = sendEmail;
    }

    @Transient
    @JsonView(AllViews.PolicyPageView.class)
    public List<Application> getApplications(){
        List<Application> applications = list();

        if(policyStatuses != null && policyStatuses.size() > 0) {

            for (PolicyStatus policyStatus : policyStatuses) {
                if (policyStatus != null)
                    applications.add(policyStatus.getApplication());
            }
        }

        return applications;
    }

    @OneToOne
    @JoinColumn(name = "filterJsonBlobId")
    @JsonView({AllViews.TableRow.class, AllViews.FormInfo.class, AllViews.PolicyPageView.class})
    public FilterJsonBlob getFilterJsonBlob() {
        return filterJsonBlob;
    }

    public void setFilterJsonBlob(FilterJsonBlob filterJsonBlob) {
        this.filterJsonBlob = filterJsonBlob;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof Policy)) return false;

        Policy that = (Policy) o;

        return name.equals(that.name);

    }

    @Override
    public int hashCode() {
        return name.hashCode();
    }
}
