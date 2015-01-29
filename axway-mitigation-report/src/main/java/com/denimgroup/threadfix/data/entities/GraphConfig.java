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
import org.codehaus.jackson.map.annotate.JsonView;

import javax.persistence.*;
import javax.validation.constraints.Size;

@Entity
@Table(name = "GraphConfig")
public class GraphConfig extends BaseEntity{

    private static final long serialVersionUID = 1175222046579045669L;

    public static final int
            NAME_LENGTH = 60,
            URL_LENGTH = 255,
            ENUM_LENGTH = 50;

    @Size(max = NAME_LENGTH, message = "{errors.maxlength} " + NAME_LENGTH + ".")

    private String name;

    private Boolean criticalVulns = false;
    private Boolean highVulns = false;
    private Boolean mediumVulns = false;
    private Boolean lowVulns = false;
    private Boolean infoVulns = false;
    private Boolean auditable = false;



    @Column(length = 50, nullable = false)
    @JsonView({AllViews.TableRow.class, AllViews.FormInfo.class, AllViews.RestView2_1.class})
    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    @Column(nullable = false)
    @JsonView({AllViews.TableRow.class, AllViews.FormInfo.class, AllViews.RestView2_1.class})
    public Boolean getCriticalVulns() {
        return criticalVulns;
    }

    public void setCriticalVulns(Boolean isCriticalVulns) {
        this.criticalVulns = isCriticalVulns;
    }

    @Column(nullable = false)
    @JsonView({AllViews.TableRow.class, AllViews.FormInfo.class, AllViews.RestView2_1.class})
    public Boolean getHighVulns() {
        return highVulns;
    }

    public void setHighVulns(Boolean isHighVulns) {
        this.highVulns = isHighVulns;
    }

    @Column(nullable = false)
    @JsonView({AllViews.TableRow.class, AllViews.FormInfo.class, AllViews.RestView2_1.class})
    public Boolean getMediumVulns() {
        return mediumVulns;
    }

    public void setMediumVulns(Boolean isMediumVulns) {
        this.mediumVulns = isMediumVulns;
    }

    @Column(nullable = false)
    @JsonView({AllViews.TableRow.class, AllViews.FormInfo.class, AllViews.RestView2_1.class})
    public Boolean getLowVulns() {
        return lowVulns;
    }

    public void setLowVulns(Boolean isLowVulns) {
        this.lowVulns = isLowVulns;
    }

    @Column(nullable = false)
    @JsonView({AllViews.TableRow.class, AllViews.FormInfo.class, AllViews.RestView2_1.class})
    public Boolean getInfoVulns() {
        return infoVulns;
    }

    public void setInfoVulns(Boolean isInfoVulns) {
        this.infoVulns = isInfoVulns;
    }

    @Column(nullable = false)
    @JsonView({AllViews.TableRow.class, AllViews.FormInfo.class, AllViews.RestView2_1.class})
    public Boolean getAuditable() {
        return auditable;
    }

    public void setAuditable(Boolean isAuditable) {
        this.auditable = isAuditable;
    }
}
