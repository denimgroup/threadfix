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

import com.denimgroup.threadfix.data.enums.EventAction;
import com.denimgroup.threadfix.views.AllViews;
import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonView;

import javax.persistence.*;

@Entity
@Table(name = "Event")
public class Event extends AuditableEntity {

    private static final long serialVersionUID = 1L;

    public static final int
            ENUM_LENGTH = 50;

    String eventAction = null;

    Boolean apiAction = false;

    private Application application;
    private User user;
    private Vulnerability vulnerability;
    private Scan scan;
    private Defect defect;
    private VulnerabilityComment comment;

    @Column(length = ENUM_LENGTH)
    @JsonView({ AllViews.TableRow.class, AllViews.FormInfo.class})
    public String getEventAction() {
        return eventAction;
    }

    public void setEventAction(String eventAction) {
        this.eventAction = eventAction;
    }

    @Transient
    @JsonIgnore
     public EventAction getEventActionEnum() {
        return EventAction.getEventAction(eventAction);
    }

    @Column
    public Boolean isApiAction() {
        return apiAction != null && apiAction;
    }

    public void setApiAction(Boolean apiAction) {
        this.apiAction = apiAction;
    }

    @ManyToOne
    @JoinColumn(name = "applicationId")
    @JsonIgnore
    public Application getApplication() {
        return application;
    }

    public void setApplication(Application application) {
        this.application = application;
    }

    @ManyToOne
    @JoinColumn(name = "userId")
    @JsonIgnore
    public User getUser() {
        return user;
    }

    public void setUser(User user) {
        this.user = user;
    }

    @ManyToOne
    @JoinColumn(name = "vulnerabilityId")
    @JsonIgnore
    public Vulnerability getVulnerability() {
        return vulnerability;
    }

    public void setVulnerability(Vulnerability vulnerability) {
        this.vulnerability = vulnerability;
    }

    @ManyToOne
    @JoinColumn(name = "scanId")
    @JsonIgnore
    public Scan getScan() {
        return scan;
    }

    public void setScan(Scan scan) {
    this.scan = scan;
        }

    @ManyToOne
    @JoinColumn(name = "defectId")
    @JsonIgnore
    public Defect getDefect() {
        return defect;
    }

    public void setDefect(Defect defect) {
        this.defect = defect;
    }

    @ManyToOne
    @JoinColumn(name = "commentId")
    @JsonIgnore
    public VulnerabilityComment getVulnerabilityComment() {
        return comment;
    }

    public void setVulnerabilityComment(VulnerabilityComment comment) {
        this.comment = comment;
    }
}
