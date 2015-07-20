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
    APPLICATION_SET_TAGS("Set Application Tags"),
    APPLICATION_SCAN_UPLOADED("Upload Application Scan"),
    APPLICATION_SCAN_DELETED("Delete Application Scan"),
    VULNERABILITY_CREATE("Create Vulnerability"),
    VULNERABILITY_OPEN_SCAN_DELETED("Open Vulnerability From Scan Deletion"),
    VULNERABILITY_OPEN_SCAN_UPLOAD("Create Vulnerability From Scan Upload"),
    VULNERABILITY_CLOSE("Close Vulnerability"),
    VULNERABILITY_CLOSE_FINDINGS_MERGE("Close Vulnerability From Findings Merge"),
    VULNERABILITY_CLOSE_SCAN_DELETED("Close Vulnerability From Scan Deletion"),
    VULNERABILITY_CLOSE_SCAN_UPLOAD("Close Vulnerability From Scan Upload"),
    VULNERABILITY_CLOSE_MANUAL("Close Vulnerability Manually"),
    VULNERABILITY_REOPEN("Reopen Vulnerability"),
    VULNERABILITY_REOPEN_SCAN_UPLOAD("Reopen Vulnerability From Scan Upload"),
    VULNERABILITY_REOPEN_MANUAL("Reopen Vulnerability Manually"),
    VULNERABILITY_MARK_FALSE_POSITIVE("Mark Vulnerability False Positive"),
    VULNERABILITY_UNMARK_FALSE_POSITIVE("Unmark Vulnerability False Positive"),
    VULNERABILITY_COMMENT("Create Vulnerability Comment"),
    VULNERABILITY_OTHER("Other Vulnerability"),
    DEFECT_SUBMIT("Submit Defect"),
    DEFECT_STATUS_UPDATED("Update Defect Status"),
    DEFECT_CLOSED("Close Defect"),
    DEFECT_APPEARED_AFTER_CLOSED("Appeared In Scan After Defect Closed");

    private static EventAction[] organizationEventActions = { APPLICATION_CREATE, APPLICATION_EDIT,
            APPLICATION_SET_TAGS, APPLICATION_SCAN_UPLOADED, APPLICATION_SCAN_DELETED };

    private static EventAction[] applicationEventActions = { APPLICATION_CREATE, APPLICATION_EDIT,
            APPLICATION_SET_TAGS, APPLICATION_SCAN_UPLOADED, APPLICATION_SCAN_DELETED };

    private static EventAction[] vulnerabilityEventActions = { VULNERABILITY_OPEN_SCAN_DELETED,
            VULNERABILITY_OPEN_SCAN_UPLOAD,
            VULNERABILITY_CLOSE_FINDINGS_MERGE,
            VULNERABILITY_CLOSE_SCAN_DELETED,
            VULNERABILITY_CLOSE_SCAN_UPLOAD,
            VULNERABILITY_REOPEN_SCAN_UPLOAD, VULNERABILITY_MARK_FALSE_POSITIVE, VULNERABILITY_UNMARK_FALSE_POSITIVE,
            VULNERABILITY_COMMENT, VULNERABILITY_OTHER, DEFECT_SUBMIT, DEFECT_STATUS_UPDATED, DEFECT_CLOSED,
            DEFECT_APPEARED_AFTER_CLOSED };

    private static EventAction[] userEventActions = { APPLICATION_CREATE, APPLICATION_EDIT,
            APPLICATION_SET_TAGS, APPLICATION_SCAN_UPLOADED, APPLICATION_SCAN_DELETED, VULNERABILITY_OPEN_SCAN_DELETED,
            VULNERABILITY_OPEN_SCAN_UPLOAD,
            VULNERABILITY_CLOSE_FINDINGS_MERGE,
            VULNERABILITY_CLOSE_SCAN_DELETED,
            VULNERABILITY_CLOSE_SCAN_UPLOAD,
            VULNERABILITY_REOPEN_SCAN_UPLOAD, VULNERABILITY_MARK_FALSE_POSITIVE,
            VULNERABILITY_UNMARK_FALSE_POSITIVE, VULNERABILITY_COMMENT, VULNERABILITY_OTHER, DEFECT_SUBMIT,
            DEFECT_STATUS_UPDATED, DEFECT_CLOSED, DEFECT_APPEARED_AFTER_CLOSED };

    EventAction(String displayName) {
        this.displayName = displayName;
    }

    private String displayName;

    @JsonView(Object.class)
    public String getDisplayName() { return displayName; }

    public boolean isOrganizationEventAction() {
        for (EventAction eventAction: organizationEventActions) {
            if (eventAction.equals(this)) {
                return true;
            }
        }
        return false;
    }

    public boolean isApplicationEventAction() {
        for (EventAction eventAction: applicationEventActions) {
            if (eventAction.equals(this)) {
                return true;
            }
        }
        return false;
    }

    public boolean isVulnerabilityEventAction() {
        for (EventAction eventAction: vulnerabilityEventActions) {
            if (eventAction.equals(this)) {
                return true;
            }
        }
        return false;
    }

    public boolean isUserEventAction() {
        for (EventAction eventAction: userEventActions) {
            if (eventAction.equals(this)) {
                return true;
            }
        }
        return false;
    }

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
