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

import javax.persistence.Entity;
import javax.persistence.Table;

/**
 * @author zabdisubhan
 *
 */
@Entity
@Table(name = "DashboardWidget")
public class DashboardWidget extends BaseEntity {

    private static final long serialVersionUID = -1612233741957801615L;

    private String widgetName;
    private String jspFilePath;

    public String getWidgetName() {
        return widgetName;
    }

    public void setWidgetName(String widgetName) {
        this.widgetName = widgetName;
    }

    public String getJspFilePath() {
        return jspFilePath;
    }

    public void setJspFilePath(String jspFilePath) {
        this.jspFilePath = jspFilePath;
    }

}
