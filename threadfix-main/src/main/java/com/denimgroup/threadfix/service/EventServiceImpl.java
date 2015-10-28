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
import java.util.*;

import static com.denimgroup.threadfix.CollectionUtils.list;

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
    public List<Event> loadAllByFinding(Finding finding) {
        return eventDao.retrieveAllByFinding(finding);
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
    public List<Event> loadAllByPolicy(Policy policy) {
        return eventDao.retrieveAllByPolicy(policy);
    }

    @Override
    public List<Event> loadAllByPolicyStatus(PolicyStatus policyStatus) {
        return eventDao.retrieveAllByPolicyStatus(policyStatus);
    }

    @Override
    public String buildUploadScanString(Scan scan) {
        return buildScanDescriptionString(scan, null);
    }

    @Override
    public String buildDeleteScanString(Scan scan) {
        Event scanUploadEvent = null;
        for (Event scanEvent : scan.getEvents()) {
            if (scanEvent.getEventActionEnum().equals(EventAction.APPLICATION_SCAN_UPLOADED)) {
                scanUploadEvent = scanEvent;
                break;
            }
        }
        return buildScanDescriptionString(scan, scanUploadEvent);
    }

    public String buildScanDescriptionString(Scan scan, Event scanUploadEvent) {
        SimpleDateFormat dateFormatter = new SimpleDateFormat("MMMM d, yyyy h:mm:ss a");

        StringBuilder scanDescription = new StringBuilder();

        String applicationChannelTypeName = null;
        String remoteProviderString = null;
        ApplicationChannel applicationChannel = scan.getApplicationChannel();
        ChannelType channelType = null;
        if (applicationChannel != null) {
            channelType = applicationChannel.getChannelType();
            if (channelType != null) {
                applicationChannelTypeName = channelType.getName();

                List<RemoteProviderType> remoteProviderTypes = channelType.getRemoteProviderTypes();
                for (RemoteProviderType remoteProviderType : remoteProviderTypes) {
                    List<RemoteProviderApplication> remoteProviderApplications = remoteProviderType.getRemoteProviderApplications();
                    for (RemoteProviderApplication remoteProviderApplication : remoteProviderApplications) {
                        Application application = remoteProviderApplication.getApplication();
                        if ((application != null) && application.equals(scan.getApplication())) {
                            remoteProviderString = remoteProviderApplication.getNativeName();
                        }
                    }
                }
            }
        }
        if (applicationChannelTypeName != null) {
            scanDescription.append(applicationChannelTypeName).append(" ");
        }

        scanDescription.append("Scan");

        String formattedImportTime = null;
        Calendar importTime = scan.getImportTime();
        if (importTime != null) {
            Date importTimeTime = importTime.getTime();
            formattedImportTime = dateFormatter.format(importTimeTime);
        }
        if (formattedImportTime != null) {
            scanDescription.append(" dated ").append(formattedImportTime);
        }

        scanDescription.append(" with ").append(scan.getNumberTotalVulnerabilities()).append(" Vulnerabilities.");

        if (remoteProviderString != null) {
            scanDescription.append(" The scan was imported from remote application ").append(remoteProviderString);
        } else {
            scanDescription.append(" The scan was uploaded");
        }

        String fileNamesString = null;
        List<String> originalFileNames = scan.getOriginalFileNames();
        if ((originalFileNames != null) && (originalFileNames.size() > 0)) {
            fileNamesString = buildFileNamesString(scan.getOriginalFileNames());
            if (fileNamesString != null) {
                scanDescription.append(" from ").append(fileNamesString);
            }
        }

        if (scanUploadEvent != null) {
            Date scanUploadEventDate = scanUploadEvent.getDate();
            if (scanUploadEventDate != null) {
                scanDescription.append(" on ").append(dateFormatter.format(scanUploadEventDate));
            }
        }

        scanDescription.append(".");
        return scanDescription.toString();
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
        applicationEvents.addAll(eventDao.retrieveUngroupedByApplication(application));
        Collections.sort(applicationEvents, eventComparator);
        return applicationEvents;
    }

    @Override
    public List<Event> getOrganizationEvents(Organization organization) {
        List<Event> organizationEvents = list();
        organizationEvents.addAll(eventDao.retrieveUngroupedByOrganization(organization));
        Collections.sort(organizationEvents, eventComparator);
        return organizationEvents;
    }

    @Override
    public List<Event> getVulnerabilityEvents(Vulnerability vulnerability) {
        List<Event> vulnerabilityEvents = list();
        vulnerabilityEvents.addAll(eventDao.retrieveUngroupedByVulnerability(vulnerability));
        Collections.sort(vulnerabilityEvents, eventComparator);
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
