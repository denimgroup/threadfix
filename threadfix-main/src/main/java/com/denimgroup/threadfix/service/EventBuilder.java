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
        event.setEventAction(eventAction.toString());
        return this;
    }

    public EventBuilder setApplication(Application application) {
        event.setApplication(application);
        return this;
    }

    public EventBuilder setUser(User user) {
        event.setUser(user);
        event.setApiAction(user == null);
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

    public EventBuilder setDefect(Defect defect) {
        event.setDefect(defect);
        return this;
    }

    public EventBuilder setVulnerabilityComment(VulnerabilityComment comment) {
        event.setVulnerabilityComment(comment);
        return this;
    }
}
