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
import com.fasterxml.jackson.annotation.JsonView;
import org.hibernate.validator.constraints.NotEmpty;

import javax.persistence.*;
import javax.validation.constraints.Size;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import static com.denimgroup.threadfix.CollectionUtils.list;

/**
 * Created by sgerick on 5/26/2015.
 */

@Entity
@Table(name = "AcceptanceCriteria")
public class AcceptanceCriteria extends AuditableEntity {

    private static final long serialVersionUID = 7188109163348903139L;

    private static final int NAME_LENGTH = 60;

    @NotEmpty(message = "{errors.required}")
    @Size(max = NAME_LENGTH, message = "{errors.maxlength} " + NAME_LENGTH + ".")
    private String name;

    private List<AcceptanceCriteriaStatus> acceptanceCriteriaStatuses;

    private FilterJsonBlob filterJsonBlob;

    @Column(length = NAME_LENGTH, nullable = false)
    @JsonView(Object.class) // This means it will be included in all ObjectWriters with Views.
    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    @OneToMany(mappedBy = "acceptanceCriteria")
    @JsonView(Object.class)
    public List<AcceptanceCriteriaStatus> getAcceptanceCriteriaStatuses() {
        return acceptanceCriteriaStatuses;
    }

    public void setAcceptanceCriteriaStatuses(List<AcceptanceCriteriaStatus> acceptanceCriteriaStatuses) {
        this.acceptanceCriteriaStatuses = acceptanceCriteriaStatuses;
    }

    @Transient
    @JsonView(Object.class)
    public List<Application> getApplications(){
        List<Application> applications = list();

        for (AcceptanceCriteriaStatus acceptanceCriteriaStatus : acceptanceCriteriaStatuses) {
            applications.add(acceptanceCriteriaStatus.getApplication());
        }

        return applications;
    }

    @OneToOne
    @JoinColumn(name = "filterJsonBlobId")
    @JsonView(AllViews.TableRow.class)
    public FilterJsonBlob getFilterJsonBlob() {
        return filterJsonBlob;
    }

    public void setFilterJsonBlob(FilterJsonBlob filterJsonBlob) {
        this.filterJsonBlob = filterJsonBlob;
    }

}
