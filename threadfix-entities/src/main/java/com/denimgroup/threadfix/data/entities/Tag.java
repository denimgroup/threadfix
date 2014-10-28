////////////////////////////////////////////////////////////////////////
//
//     Copyright (c) 2009-2014 Denim Group, Ltd.
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

import org.codehaus.jackson.annotate.JsonIgnore;
import org.codehaus.jackson.map.annotate.JsonView;
import org.hibernate.validator.constraints.NotEmpty;

import javax.persistence.*;
import javax.validation.constraints.Size;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * Created by stran on 10/13/2014.
 */

@Entity
@Table(name = "Tag")
public class Tag extends AuditableEntity {
    private static final long serialVersionUID = 6892872482302897120L;
    private static final int NAME_LENGTH = 60;

    @NotEmpty(message = "{errors.required}")
    @Size(max = NAME_LENGTH, message = "{errors.maxlength} " + NAME_LENGTH + ".")
    private String name;

    private Set<Application> applications = new HashSet<Application>(0);
    private Set<VulnerabilityComment> vulnerabilityComments = new HashSet<VulnerabilityComment>(0);

    @Column(length = NAME_LENGTH, nullable = false)
    @JsonView(Object.class)
    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    @ManyToMany(mappedBy = "tags")
    @JsonIgnore
    public Set<Application> getApplications() {
        return applications;
    }

    public void setApplications(Set<Application> applications) {
        this.applications = applications;
    }

    @ManyToMany(fetch = FetchType.LAZY, mappedBy = "tags")
    @JsonIgnore
    public Set<VulnerabilityComment> getVulnerabilityComments() {
        return vulnerabilityComments;
    }

    public void setVulnerabilityComments(Set<VulnerabilityComment> vulnerabilityComments) {
        this.vulnerabilityComments = vulnerabilityComments;
    }

    @Transient
    public boolean getDeletable(){
        return applications.size()==0 && vulnerabilityComments.size()==0;
    }

}
