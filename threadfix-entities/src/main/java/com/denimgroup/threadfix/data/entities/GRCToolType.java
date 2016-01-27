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

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonView;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.OneToMany;
import javax.persistence.Table;
import java.util.List;

/**
 * @author zabdisubhan
 *
 */
@Entity
@Table(name = "GRCToolType")
public class GRCToolType extends BaseEntity {

    private static final long serialVersionUID = -6209803700465606694L;

    public static final String SERVICE_NOW = "Service Now";

    private String name;
    private String fullClassName;

    private List<GRCTool> grcTools;

    @Column(length = 25, nullable = false)
    @JsonView(Object.class) // This means it will be included in all ObjectWriters with Views.
    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    @OneToMany(mappedBy = "grcToolType")
    @JsonIgnore
    public List<GRCTool> getGrcTools() {
        return grcTools;
    }

    public void setGrcTools(List<GRCTool> grcTools) {
        this.grcTools = grcTools;
    }

    @Column(length = 512)
    public String getFullClassName() {
        return fullClassName;
    }

    public void setFullClassName(String fullClassName) {
        this.fullClassName = fullClassName;
    }

}