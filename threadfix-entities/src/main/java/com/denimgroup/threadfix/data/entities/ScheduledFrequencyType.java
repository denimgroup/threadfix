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

/**
 * Created by zabdisubhan on 8/14/14.
 */

public enum ScheduledFrequencyType {
    DAILY("Daily"),
    WEEKLY("Weekly");

    private String description;

    public String getDescription() {
        return this.description;
    }

    ScheduledFrequencyType(String description) {
        this.description = description;
    }

    public static ScheduledFrequencyType getFrequency(String keyword) {
        for (ScheduledFrequencyType t: values()) {
            if (keyword.equalsIgnoreCase(t.getDescription())) {
                return t;
            }
        }
        return null;
    }
}