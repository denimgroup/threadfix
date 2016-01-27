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

package com.denimgroup.threadfix.data.dao;

import com.denimgroup.threadfix.data.entities.*;
import com.denimgroup.threadfix.data.enums.EventAction;

import java.util.Date;
import java.util.List;
import java.util.Set;

public interface EventDao extends GenericObjectDao<Event> {

    List<Event> retrieveAllByScan(Scan scan);

    List<Event> retrieveAllByFinding(Finding finding);

    List<Event> retrieveAllByApplication(Application application);

    List<Event> retrieveAllByVulnerability(Vulnerability vulnerability);

    List<Event> retrieveAllByDefect(Defect defect);

    List<Event> retrieveAllByDefectTrackerId(Integer defectTrackerId);

    List<Event> retrieveAllByPolicy(Policy policy);

    List<Event> retrieveAllByPolicyStatus(PolicyStatus policyStatus);

    List<Event> retrieveUngroupedByApplication(Application application);

    List<Event> retrieveUngroupedByOrganization(Organization organization);

    List<Event> retrieveUngroupedByVulnerability(Vulnerability vulnerability);

    List<Event> retrieveUngroupedByUser(User user);

    List<Event> retrieveGroupedByUser(User user);

    List<Event> retrieveGlobalUngrouped(Set<Integer> appIds, Set<Integer> teamIds);

    List<Event> retrieveGlobalGrouped(Set<Integer> appIds, Set<Integer> teamIds);

    List<Event> retrieveRecentUngrouped(Set<EventAction> userEventActions, Date startTime, Date stopTime, Set<Integer> appIds, Set<Integer> teamIds);

    List<Event> retrieveRecentGrouped(Set<EventAction> userGroupedEventActions, Date startTime, Date stopTime, Set<Integer> appIds, Set<Integer> teamIds);
}
