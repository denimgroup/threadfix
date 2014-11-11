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
import org.codehaus.jackson.annotate.JsonIgnore;
import org.codehaus.jackson.map.annotate.JsonView;

import javax.persistence.*;
import java.util.List;

/**
 * Created by mac on 11/6/14.
 */
@Entity
@Table(name = "ActivityType")
public class ActivityType extends BaseEntity {

    private String name, formatString;
    private List<Activity> activities;

    @OneToMany(mappedBy = "activityType")
    @OrderBy("createdDate")
    @JsonIgnore
    public List<Activity> getActivities() {
        return activities;
    }

    public void setActivities(List<Activity> activities) {
        this.activities = activities;
    }

    @JsonView(AllViews.FormInfo.class)
    @Column
    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    @Column
    @JsonView(AllViews.FormInfo.class)
    public String getFormatString() {
        return formatString;
    }

    public void setFormatString(String formatString) {
        this.formatString = formatString;
    }
}
