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

    private Integer applicationId;
    private Integer userId;
    private Integer vulnerabilityId;
    private Integer scanId;
    private Integer defectId;
    private Integer commentId;

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

    @Column
    @JsonView({AllViews.TableRow.class, AllViews.FormInfo.class})
    public Integer getApplicationId() {
        return applicationId;
    }

    public void setApplicationId(Integer applicationId) {
        this.applicationId = applicationId;
    }

    @Column
    @JsonView({AllViews.TableRow.class, AllViews.FormInfo.class})
    public Integer getUserId() {
        return userId;
    }

    public void setUserId(Integer userId) {
        this.userId = userId;
    }

    @Column
    @JsonView({AllViews.TableRow.class, AllViews.FormInfo.class})
    public Integer getVulnerabilityId() {
        return vulnerabilityId;
    }

    public void setVulnerabilityId(Integer vulnerabilityId) {
        this.vulnerabilityId = vulnerabilityId;
    }

    @Column
    @JsonView({AllViews.TableRow.class, AllViews.FormInfo.class})
    public Integer getScanId() {
        return scanId;
    }

    public void setScanId(Integer scanId) {
        this.scanId = scanId;
    }

    @Column
    @JsonView({AllViews.TableRow.class, AllViews.FormInfo.class})
    public Integer getDefectId() {
        return defectId;
    }

    public void setDefectId(Integer defectId) {
        this.defectId = defectId;
    }

    @Column
    @JsonView({AllViews.TableRow.class, AllViews.FormInfo.class})
    public Integer getCommentId() {
        return commentId;
    }

    public void setCommentId(Integer commentId) {
        this.commentId = commentId;
    }
}
