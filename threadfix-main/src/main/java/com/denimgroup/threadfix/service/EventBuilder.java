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
package com.denimgroup.threadfix.service;

import com.denimgroup.threadfix.data.entities.*;
import com.denimgroup.threadfix.data.enums.EventAction;
import com.denimgroup.threadfix.logging.SanitizedLogger;

public class EventBuilder {

    private final SanitizedLogger log = new SanitizedLogger(EventBuilder.class);

    Event event = new Event();

    public Event generateEvent() {
        return event;
    }

    public EventBuilder setEventAction(EventAction eventAction) {
        if (eventAction != null) {
            event.setEventAction(eventAction.toString());
        } else {
            event.setEventAction(null);
        }
        return this;
    }

    public EventBuilder setApplication(Application application) {
        event.setApplication(application);
        return this;
    }

    public EventBuilder setUser(User user) {
        event.setUser(user);
        if (user != null) {
            event.setApiAction(false);
        } else {
            event.setApiAction(true);
        }
        return this;
    }

    public EventBuilder setVulnerability(Vulnerability vulnerability) {
        event.setVulnerability(vulnerability);
        return this;
    }

    public EventBuilder setScan(Scan scan) {
        event.setScan(scan);
        return this;
    }

    public EventBuilder setFinding(Finding finding) {
        event.setFinding(finding);
        return this;
    }

    public EventBuilder setDeletedScanId(Integer deletedScanId) {
        event.setDeletedScanId(deletedScanId);
        return this;
    }

    public EventBuilder setDefect(Defect defect) {
        event.setDefect(defect);
        return this;
    }

    public EventBuilder setVulnerabilityComment(VulnerabilityComment comment) {
        event.setVulnerabilityComment(comment);
        return this;
    }

    public EventBuilder setDetail(String detail) {
        event.setDetail(detail);
        return this;
    }

    public EventBuilder setStatus(String status) {
        event.setStatus(status);
        return this;
    }

    public EventBuilder setPolicy(Policy policy) {
        event.setPolicy(policy);
        return this;
    }

    public EventBuilder setPolicyStatus(PolicyStatus policyStatus) {
        event.setPolicyStatus(policyStatus);
        return this;
    }
}
