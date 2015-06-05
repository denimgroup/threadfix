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
import org.hibernate.validator.constraints.NotEmpty;

import javax.persistence.*;
import javax.validation.constraints.Size;
import java.util.ArrayList;
import java.util.List;

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

//    private List<Application> applications = new ArrayList<Application>();

//    private FilterJsonBlob filterJsonBlob;

    @Column(length = NAME_LENGTH, nullable = false)
    @JsonView(Object.class) // This means it will be included in all ObjectWriters with Views.
    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

//    @ManyToMany(cascade = CascadeType.ALL)
//    @JoinTable(name="AcceptanceCriteria_Application",
//            joinColumns={@JoinColumn(name="AcceptanceCriteria_Id")},
//            inverseJoinColumns={@JoinColumn(name="Application_Id")})
//    @JsonIgnore
//    public List<Application> getApplications() {
//        return applications;
//    }
//
//    public void setApplications(List<Application> applications) {
//        this.applications = applications;
//    }

//    @OneToOne
//    @JoinColumn(name = "filterJsonBlobId")
//    @JsonIgnore
//    public FilterJsonBlob getFilterJsonBlob() {
//        return filterJsonBlob;
//    }
//
//    public void setFilterJsonBlob(FilterJsonBlob filterJsonBlob) {
//        this.filterJsonBlob = filterJsonBlob;
//    }

}
