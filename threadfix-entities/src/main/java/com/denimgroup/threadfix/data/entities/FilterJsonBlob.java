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

import org.codehaus.jackson.annotate.JsonAutoDetect;
import org.codehaus.jackson.annotate.JsonMethod;
import org.codehaus.jackson.annotate.JsonProperty;
import org.codehaus.jackson.map.annotate.JsonView;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.Table;
import javax.persistence.Transient;

@Entity
@Table(name = "FilterJsonBlob")
@JsonAutoDetect(value = { JsonMethod.NONE })
public class FilterJsonBlob extends AuditableEntity {

    private String json, name;
    private Boolean defaultTrending;

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

    @Transient
    @Override
    public String toString() {
        return json;
    }
}
