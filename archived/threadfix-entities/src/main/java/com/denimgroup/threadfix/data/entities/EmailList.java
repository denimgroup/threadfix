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

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonView;
import org.hibernate.annotations.CollectionOfElements;
import org.hibernate.validator.constraints.NotEmpty;

import javax.persistence.*;
import javax.validation.constraints.Size;
import java.util.List;

/**
 * @author zabdisubhan
 */

@Entity
@Table(name = "EmailList")
public class EmailList extends AuditableEntity {

    private static final long serialVersionUID = 2874752871948132066L;
    private static final int NAME_LENGTH = 60;
    private static final int EMAIL_LENGTH = 128;

    @NotEmpty(message = "{errors.required}")
    @Size(max = NAME_LENGTH, message = "{errors.maxlength} " + NAME_LENGTH + ".")
    private String name;
    @Size(max = EMAIL_LENGTH, message = "{errors.maxlength} " + EMAIL_LENGTH + ".")
    private List<String> emailAddresses;
    private List<ScheduledEmailReport> scheduledEmailReports;

    @Column(length = NAME_LENGTH, nullable = false)
    @JsonView(Object.class)
    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    @CollectionOfElements // for sonar
    @ElementCollection
    @Column(name = "emailAddress", length = EMAIL_LENGTH)
    @CollectionTable(name = "EmailAddress", joinColumns = @JoinColumn(name = "EmailListId"))
    @JsonView(Object.class)
    public List<String> getEmailAddresses() {
        return emailAddresses;
    }

    public void setEmailAddresses(List<String> emailAddresses) {
        this.emailAddresses = emailAddresses;
    }

    @ManyToMany(mappedBy = "emailLists")
    @JsonIgnore()
    public List<ScheduledEmailReport> getScheduledEmailReports() {
        return scheduledEmailReports;
    }

    public void setScheduledEmailReports(List<ScheduledEmailReport> scheduledEmailReports) {
        this.scheduledEmailReports = scheduledEmailReports;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof EmailList)) return false;

        EmailList emailList = (EmailList) o;
        return !(name != null ? !name.equals(emailList.name) : emailList.name != null);
    }

    @Override
    public int hashCode() {
        return name != null ? name.hashCode() : 0;
    }
}
