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
import javax.validation.constraints.Size;
import java.io.Serializable;
import java.util.List;
import java.util.Map;

import static com.denimgroup.threadfix.CollectionUtils.map;

/**
 * @author zabdisubhan
 *
 */
@Entity
@Table(name = "GRCApplication")
public class GRCApplication extends AuditableEntity {

    public static final int NATIVE_ID_LENGTH = 32;
    public static final int POLICY_NUMBER_LENGTH = 32;
    public static final int NAME_LENGTH = 1024;

    @Size(max = NATIVE_ID_LENGTH, message = "{errors.maxlength} " + NATIVE_ID_LENGTH + ".")
    private String nativeId;

    @Size(max = NAME_LENGTH, message = "{errors.maxlength} " + NAME_LENGTH + ".")
    private String name;

    @Size(max = POLICY_NUMBER_LENGTH, message = "{errors.maxlength} " + POLICY_NUMBER_LENGTH + ".")
    private String policyNumber;

    private GRCTool grcTool;

    private Application application;

    private Map applicationJson;

    private List<GRCControl> grcControls;

    @JsonView(Object.class)
    public String getNativeId() {
        return nativeId;
    }

    public void setNativeId(String nativeId) {
        this.nativeId = nativeId;
    }

    @JsonView(Object.class)
    public String getPolicyNumber() {
        return policyNumber;
    }

    public void setPolicyNumber(String policyNumber) {
        this.policyNumber = policyNumber;
    }

    @JsonView(Object.class)
    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    @OneToOne
    @JsonIgnore
    @JoinColumn(name = "applicationId")
    public Application getApplication() {
        return application;
    }

    @Transient
    @JsonProperty("application")
    @JsonView(Object.class)
    public Map<String, ? extends Serializable> getApplicationJson() {
        if(application != null) {
            return map(
                    "id", application.getId(),
                    "name", application.getName(),
                    "teamName", application.getOrganization().getName(),
                    "teamId", application.getOrganization().getId());
        } else {
            return null;
        }
    }

    public void setApplication(Application application) {
        this.application = application;
    }

    @OneToMany(mappedBy = "grcApplication", cascade = CascadeType.ALL)
    @JsonIgnore
    public List<GRCControl> getGrcControls() {
        return grcControls;
    }

    public void setGrcControls(List<GRCControl> grcControls) {
        this.grcControls = grcControls;
    }

    @ManyToOne
    @JoinColumn(name = "grcToolId")
    @JsonIgnore
    public GRCTool getGrcTool() {
        return grcTool;
    }

    public void setGrcTool(GRCTool grcTool) {
        this.grcTool = grcTool;
    }
}
