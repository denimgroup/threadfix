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
import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonView;

import javax.annotation.Nullable;
import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.Table;
import javax.persistence.Transient;
import javax.validation.constraints.Size;
import java.util.Map;

import static com.denimgroup.threadfix.CollectionUtils.map;

@Entity
@Table(name = "Dependency")
public class Dependency extends AuditableEntity {

    private static Map<String, String> refLinkMap = map(
            "cve", "http://cve.mitre.org/cgi-bin/cvename.cgi?name=",
            "osvdb", "http://osvdb.org/",
            "nessus", "http://www.tenable.com/plugins/index.php?view=single&id=");

    private static final long serialVersionUID = 3647499545381978852L;

    @Size(max = 20, message = "{errors.maxlength} 20.")
    private String cve;

    @Size(max = 1024)
    private String componentName = null;

    @Size(max = 1024)
    private String componentFilePath = null;

    @Size(max = 1024)
    private String refLink = null;

    @Size(max = 1024000)
    private String description = null;

    @Size(max = 20, message = "{errors.maxlength} 20.")
    private String source;

    @Nullable
    @Column(nullable = true)
    @JsonView({ AllViews.UIVulnSearch.class, AllViews.VulnerabilityDetail.class })
    public String getComponentName() {
        return componentName;
    }

    public void setComponentName(String componentName) {
        this.componentName = componentName;
    }

    @Nullable
    @Column(nullable = true)
    @JsonView(AllViews.VulnerabilityDetail.class)
    public String getComponentFilePath() {
        return componentFilePath;
    }

    public void setComponentFilePath(String componentFilePath) {
        this.componentFilePath = componentFilePath;
    }

    @Nullable
    @Column(nullable = true)
    @JsonView({ AllViews.UIVulnSearch.class, AllViews.VulnerabilityDetail.class })
    public String getDescription() {
        return description;
    }

    public void setDescription(String description) {
        this.description = description;
    }

    @Column(length = 20)
    @JsonIgnore
    public String getCve() {
        return cve;
    }

    public void setCve(String cve) {
        this.cve = cve;
    }

    @Nullable
    @Column(length = 20)
    @JsonView(Object.class)
    public String getSource() {
        return source;
    }

    public void setSource(String source) {
        this.source = source;
    }

    /**
     * This is used to identify the dependency in an unambiguous way.
     * @return
     */
    @Transient
    @JsonIgnore
    public String getKey() {
        return componentName + " - " + getCve();
    }

    @Override
    public String toString() {
        return "Dependency{" +
                "cve='" + cve + '\'' +
                ", componentName='" + componentName + '\'' +
                ", description='" + description + '\'' +
                '}';
    }

    @JsonView(Object.class)
    public String getRefLink() {
        if (this.refLink != null)
            return this.refLink;

        String src = (getSource() != null && refLinkMap.get(getSource().toLowerCase()) != null ? getSource() : "cve");
        return refLinkMap.get(src) + getCve();
    }

    public void setRefLink(String refLink) {
        this.refLink = refLink;
    }

    @Transient
    @JsonView(Object.class)
    public String getRefId() {
        if (getSource() != null && getSource().toUpperCase().equals("OSVDB")) {
            return "osvdb-" + getCve();
        } else {
            return getCve();
        }
    }
}
