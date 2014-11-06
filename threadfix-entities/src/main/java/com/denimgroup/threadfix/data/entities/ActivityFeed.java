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
@Table(name = "ActivityFeed")
public class ActivityFeed extends BaseEntity {

    private long objectId;

    private ActivityFeedType activityFeedType;

    private List<Activity> activityList;

    @Column
    public long getObjectId() {
        return objectId;
    }

    public void setObjectId(long objectId) {
        this.objectId = objectId;
    }

    @ManyToOne
    @JoinColumn(name = "activityFeedTypeId")
    public ActivityFeedType getActivityFeedType() {
        return activityFeedType;
    }

    public void setActivityFeedType(ActivityFeedType activityFeedType) {
        this.activityFeedType = activityFeedType;
    }

    @JsonView(AllViews.FormInfo.class)
    @ManyToMany(fetch = FetchType.LAZY, cascade = CascadeType.ALL)
    @JoinTable(name = "activity_feed_join",
            joinColumns = {
                @JoinColumn(name = "activityFeedId", nullable = false, updatable = false)
            },
            inverseJoinColumns = {
                @JoinColumn(name = "activityId", nullable = false, updatable = false)
            }
    )
    public List<Activity> getActivityList() {
        return activityList;
    }

    public void setActivityList(List<Activity> activityList) {
        this.activityList = activityList;
    }
}
