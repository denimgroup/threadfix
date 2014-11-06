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

import com.denimgroup.threadfix.views.AllViews;
import org.codehaus.jackson.map.annotate.JsonView;

import javax.persistence.*;
import java.util.List;

/**
 * Created by mac on 11/6/14.
 */
@Entity
@Table(name = "Activity")
public class Activity extends AuditableEntity {

    private User user;

    private ActivityType activityType;

    private long objectId, parentId;

    private List<ActivityFeed> activityFeedList;

    @Column
    @JsonView(AllViews.FormInfo.class)
    public String getLinkPath() {
        return linkPath;
    }

    public void setLinkPath(String linkPath) {
        this.linkPath = linkPath;
    }

    @Column
    @JsonView(AllViews.FormInfo.class)
    public String getLinkText() {
        return linkText;
    }

    public void setLinkText(String linkText) {
        this.linkText = linkText;
    }

    @Column
    @JsonView(AllViews.FormInfo.class)
    public String getDetails() {
        return details;
    }

    public void setDetails(String details) {
        this.details = details;
    }

    private String details, linkText, linkPath;

    @ManyToOne
    @JoinColumn(name = "userId")
    @JsonView(AllViews.FormInfo.class)
    public User getUser() {
        return user;
    }

    public void setUser(User user) {
        this.user = user;
    }

    @ManyToOne
    @JoinColumn(name = "activityTypeId")
    @JsonView(AllViews.FormInfo.class)
    public ActivityType getActivityType() {
        return activityType;
    }

    public void setActivityType(ActivityType activityType) {
        this.activityType = activityType;
    }

    @Column
    @JsonView()
    public long getObjectId() {
        return objectId;
    }

    public void setObjectId(long objectId) {
        this.objectId = objectId;
    }

    @Column
    public long getParentId() {
        return parentId;
    }

    public void setParentId(long parentId) {
        this.parentId = parentId;
    }

    @ManyToMany(fetch = FetchType.LAZY, mappedBy = "activityList")
    public List<ActivityFeed> getActivityFeedList() {
        return activityFeedList;
    }

    public void setActivityFeedList(List<ActivityFeed> activityFeedList) {
        this.activityFeedList = activityFeedList;
    }

    @Transient
    @JsonView(AllViews.FormInfo.class)
    public long getDate() {
        return getCreatedDate().getTime();
    }

}
