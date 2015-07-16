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
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonView;

import javax.persistence.*;

@Entity
@Table(name = "FilterJsonBlob")
//@JsonAutoDetect(value = { JsonMethod.NONE }) TODO figure this out
public class FilterJsonBlob extends AuditableEntity {

    private String json, name;
    private Boolean defaultTrending;

    private AcceptanceCriteria acceptanceCriteria;

    @JsonProperty
    @JsonView(Object.class)
    @Column(length = 2048)
    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    @JsonView(Object.class)
    @Column(length = 102400)
    @JsonProperty
    public String getJson() {
        return json;
    }

    public void setJson(String json) {
        this.json = json;
    }

    @JsonView(Object.class)
    @JsonProperty
    @Column(nullable = true)
    public Boolean getDefaultTrending() {
        return defaultTrending == null ? false : defaultTrending;
    }

    public void setDefaultTrending(Boolean defaultTrending) {
        this.defaultTrending = defaultTrending;
    }

    @OneToOne(mappedBy = "filterJsonBlob")
//    @JoinColumn(name = "acceptanceCriteriaId")
    @JsonIgnore
    public AcceptanceCriteria getAcceptanceCriteria() {
        return acceptanceCriteria;
    }

    public void setAcceptanceCriteria(AcceptanceCriteria acceptanceCriteria) {
        this.acceptanceCriteria = acceptanceCriteria;
    }

    @Transient
    @Override
    public String toString() {
        return json;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof FilterJsonBlob)) return false;

        FilterJsonBlob that = (FilterJsonBlob) o;

        return name.equals(that.name);

    }

    @Override
    public int hashCode() {
        return name.hashCode();
    }
}
