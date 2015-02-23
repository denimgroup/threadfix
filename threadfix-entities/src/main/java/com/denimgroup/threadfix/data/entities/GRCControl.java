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

import javax.persistence.*;
import javax.validation.constraints.Size;
import java.util.Set;

import static com.denimgroup.threadfix.CollectionUtils.set;

/**
 * @author zabdisubhan
 *
 */
@Entity
@Table(name = "GRCControl")
public class GRCControl extends AuditableEntity {

    public static final int NATIVE_ID_LENGTH = 32;
    public final static int URL_LENGTH = 255;
    public final static int STATUS_LENGTH = 32;

    // TODO make this smarter
    public final static Set<String> OPEN_CODES   = set("Impaired", "Proposed");
    public final static Set<String> CLOSED_CODES = set("Active");

    @Size(max = NATIVE_ID_LENGTH, message = "{errors.maxlength} " + NATIVE_ID_LENGTH + ".")
    private String nativeId;

    @Size(max = STATUS_LENGTH, message = "{errors.maxlength} " + STATUS_LENGTH + ".")
    private String status;

    @Size(max = URL_LENGTH, message = "{errors.maxlength} " + URL_LENGTH + ".")
    private String referenceUrl;

    private Vulnerability vulnerability;

    private GRCApplication grcApplication;

    private String controlId;

    @JsonView({AllViews.TableRow.class})
    public String getNativeId(){
        return nativeId;
    }

    public void setNativeId(String nativeId) {
        this.nativeId = nativeId;
    }

    @OneToOne
    @JoinColumn(name = "vulnerabilityId")
    public Vulnerability getVulnerability() {
        return vulnerability;
    }

    public void setVulnerability(Vulnerability vulnerability) {
        this.vulnerability = vulnerability;
    }

    @ManyToOne
    @JoinColumn(name = "grcApplicationId")
    @JsonView({AllViews.TableRow.class})
    public GRCApplication getGrcApplication() {
        return grcApplication;
    }

    @Column(length = 50)
    @JsonView({AllViews.TableRow.class, AllViews.VulnSearch.class})
    public String getControlId() {
        return controlId;
    }

    public void setControlId(String controlId) {
        this.controlId = controlId;
    }

    public void setGrcApplication(GRCApplication grcApplication) {
        this.grcApplication = grcApplication;
    }

    @JsonView({AllViews.TableRow.class, AllViews.VulnSearch.class})
    public String getStatus() {
        return status;
    }

    public void setStatus(String status) {
        this.status = status;
    }

    @Column(length = 255)
    @JsonView({AllViews.TableRow.class, AllViews.VulnSearch.class})
    public String getReferenceUrl() {
        return referenceUrl;
    }

    public void setReferenceUrl(String referenceUrl) {
        this.referenceUrl = referenceUrl;
    }

    @Transient
    @JsonView({AllViews.TableRow.class, AllViews.VulnSearch.class})
    private String getBugImageName() {
        String color = OPEN_CODES.contains(status) ? "red" :
                CLOSED_CODES.contains(status) ? "grn" :
                        "blk";
        return "icn_bug_" + color + "_stroke.png";
    }

}
