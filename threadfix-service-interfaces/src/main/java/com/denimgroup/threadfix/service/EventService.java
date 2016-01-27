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

package com.denimgroup.threadfix.service;

import com.denimgroup.threadfix.data.entities.*;
import com.denimgroup.threadfix.data.enums.EventAction;

import java.util.Date;
import java.util.List;
import java.util.Set;

public interface EventService extends GenericObjectService<Event> {

    List<Event> loadAllByScan(Scan scan);

    List<Event> loadAllByFinding(Finding finding);

    List<Event> loadAllByVulnerability(Vulnerability vulnerability);

    List<Event> loadAllByDefect(Defect defect);

    List<Event> loadAllByDefectTrackerId(Integer defectTrackerId);

    List<Event> loadAllByPolicy(Policy policy);

    List<Event> loadAllByPolicyStatus(PolicyStatus policyStatus);

    String buildUploadScanString(Scan scan);

    String buildDeleteScanString(Scan scan);

    List<Event> getApplicationEvents(Application application);

    List<Event> getOrganizationEvents(Organization organization);

    List<Event> getVulnerabilityEvents(Vulnerability vulnerability);

    List<Event> getUserEvents(User user);

    List<Event> getGlobalEvents(Set<Integer> appIds, Set<Integer> teamIds);

    List<Event> getRecentEvents(Set<EventAction> userEventActions, Set<EventAction> userGroupedEventActions,
                                Date startTime, Date stopTime, Set<Integer> appIds, Set<Integer> teamIds);
}
