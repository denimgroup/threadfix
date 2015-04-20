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
package com.denimgroup.threadfix.data.enums;

import com.fasterxml.jackson.annotation.JsonView;

public enum EventAction {
    APPLICATION_CREATE("Create Application"),
    APPLICATION_EDIT("Edit Application"),
    APPLICATION_SCAN_UPLOADED("Upload Application Scan");

    EventAction(String displayName) {
        this.displayName = displayName;
    }

    private String displayName;

    @JsonView(Object.class)
    public String getDisplayName() { return displayName; }

    public static EventAction getEventAction(String input) {
        EventAction action = null; // no default event action

        for (EventAction eventAction : values()) {
            if (eventAction.toString().equals(input) ||
                    eventAction.displayName.equals(input) ||
                    eventAction.displayName.replace(' ', '_').equals(input)) {
                action = eventAction;
                break;
            }
        }

        return action;
    }
}
