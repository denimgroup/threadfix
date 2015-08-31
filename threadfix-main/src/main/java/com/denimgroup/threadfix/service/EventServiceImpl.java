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

import com.denimgroup.threadfix.data.dao.EventDao;
import com.denimgroup.threadfix.data.dao.GenericObjectDao;
import com.denimgroup.threadfix.data.entities.*;
import com.denimgroup.threadfix.data.enums.EventAction;
import com.denimgroup.threadfix.logging.SanitizedLogger;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.text.SimpleDateFormat;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.Set;

import static com.denimgroup.threadfix.CollectionUtils.list;
import static java.util.Collections.sort;

@Service
@Transactional
public class EventServiceImpl extends AbstractGenericObjectService<Event> implements EventService {

    private final SanitizedLogger log = new SanitizedLogger(EventService.class);

    @Autowired
    private EventDao eventDao;
    @Autowired
    private UserService userService;

    private EventComparator eventComparator = new EventComparator(false);

    @Override
    GenericObjectDao<Event> getDao() {
        return eventDao;
    }

    @Override
    public List<Event> loadAllByScan(Scan scan) {
        return eventDao.retrieveAllByScan(scan);
    }

    @Override
    public List<Event> loadAllByVulnerability(Vulnerability vulnerability) {
        return eventDao.retrieveAllByVulnerability(vulnerability);
    }

    @Override
    public List<Event> loadAllByDefect(Defect defect) {
        return eventDao.retrieveAllByDefect(defect);
    }

    @Override
    public List<Event> loadAllByAcceptanceCriteria(AcceptanceCriteria acceptanceCriteria) {
        return eventDao.retrieveAllByAcceptanceCriteria(acceptanceCriteria);
    }

    @Override
    public List<Event> loadAllByAcceptanceCriteriaStatus(AcceptanceCriteriaStatus acceptanceCriteriaStatus) {
        return eventDao.retrieveAllByAcceptanceCriteriaStatus(acceptanceCriteriaStatus);
    }

    @Override
    public String buildUploadScanString(Scan scan) {
        SimpleDateFormat dateFormatter = new SimpleDateFormat("MMMM d, yyyy h:mm:ss a");

        String uploadScanString = scan.getApplicationChannel().getChannelType().getName() +
                " Scan dated " + dateFormatter.format(scan.getImportTime().getTime()) + " with " + scan.getNumberTotalVulnerabilities() +
                " Vulnerabilities. The scan was uploaded from " + buildFileNamesString(scan.getOriginalFileNames()) + ".";

        return uploadScanString;
    }

    @Override
    public String buildDeleteScanString(Scan scan) {
        SimpleDateFormat dateFormatter = new SimpleDateFormat("MMMM d, yyyy h:mm:ss a");

        Event scanUploadEvent = null;
        for (Event scanEvent: loadAllByScan(scan)) {
            if (scanEvent.getEventActionEnum().equals(EventAction.APPLICATION_SCAN_UPLOADED)) {
                scanUploadEvent = scanEvent;
                break;
            }
        }

        String deleteScanString = scan.getApplicationChannel().getChannelType().getName() +
                " Scan dated " + dateFormatter.format(scan.getImportTime().getTime()) + " with " + scan.getNumberTotalVulnerabilities() +
                " Vulnerabilities. The scan was uploaded from " + buildFileNamesString(scan.getOriginalFileNames());
        if (scanUploadEvent != null) {
            deleteScanString += " on " + dateFormatter.format(scanUploadEvent.getDate());
        }
        deleteScanString += ".";

        return deleteScanString;

    }

    private String buildFileNamesString(List<String> fileNameList) {
        StringBuilder fileNames = new StringBuilder();
        int i = 0;
        int numberOfFileNames = fileNameList.size();
        for (String fileName : fileNameList) {
            fileNames.append(fileName);
            i++;
            if (i < numberOfFileNames) {
                fileNames.append(", ");
                if (i == numberOfFileNames - 1) {
                    fileNames.append("and ");
                }
            }
        }
        return fileNames.toString();
    }

    @Override
    public List<Event> getApplicationEvents(Application application) {
        List<Event> applicationEvents = list();
        for (Event event : application.getEvents()) {
            if (event.getEventActionEnum().isApplicationEventAction()) {
                applicationEvents.add(event);
            }
        }
        sort(applicationEvents, eventComparator);
        return applicationEvents;
    }

    @Override
    public List<Event> getOrganizationEvents(Organization organization) {
        List<Event> organizationEvents = list();
        for (Application application: organization.getApplications()) {
            for (Event event: application.getEvents()) {
                if (event.getEventActionEnum().isOrganizationEventAction()) {
                    organizationEvents.add(event);
                }
            }
        }
        sort(organizationEvents, eventComparator);
        return organizationEvents;
    }

    @Override
    public List<Event> getVulnerabilityEvents(Vulnerability vulnerability) {
        List<Event> vulnerabilityEvents = list();
        for (Event event : vulnerability.getEvents()) {
            if (event.getEventActionEnum().isVulnerabilityEventAction()) {
                vulnerabilityEvents.add(event);
            }
        }
        if (vulnerability.getDefect() != null) {
            for (Event event : vulnerability.getDefect().getEvents()) {
                if (event.getEventActionEnum().isVulnerabilityEventAction()) {
                    vulnerabilityEvents.add(event);
                }
            }
        }
        sort(vulnerabilityEvents, eventComparator);
        return vulnerabilityEvents;
    }

    @Override
    public List<Event> getUserEvents(User user) {
        List<Event> userEvents = list();
        userEvents.addAll(eventDao.retrieveUngroupedByUser(user));
        userEvents.addAll(eventDao.retrieveGroupedByUser(user));
        Collections.sort(userEvents, eventComparator);
        return userEvents;
    }

    @Override
    public List<Event> getGlobalEvents(Set<Integer> appIds, Set<Integer> teamIds) {
        List<Event> globalEvents = list();
        globalEvents.addAll(eventDao.retrieveGlobalUngrouped(appIds, teamIds));
        globalEvents.addAll(eventDao.retrieveGlobalGrouped(appIds, teamIds));
        Collections.sort(globalEvents, eventComparator);
        return globalEvents;
    }

    @Override
    public List<Event> getRecentEvents(Set<EventAction> userEventActions, Set<EventAction> userGroupedEventActions,
                                       Date startTime, Date stopTime, Set<Integer> appIds, Set<Integer> teamIds) {
        List<Event> recentEvents = list();
        if ((userEventActions != null) && (!userEventActions.isEmpty())) {
            recentEvents.addAll(eventDao.retrieveRecentUngrouped(userEventActions, startTime, stopTime, appIds, teamIds));
        }
        if ((userGroupedEventActions != null) && (!userGroupedEventActions.isEmpty())) {
            recentEvents.addAll(eventDao.retrieveRecentGrouped(userGroupedEventActions, startTime, stopTime, appIds, teamIds));
        }
        Collections.sort(recentEvents, eventComparator);
        return recentEvents;
    }

}
