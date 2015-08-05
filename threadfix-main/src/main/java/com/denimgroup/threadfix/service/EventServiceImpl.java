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
import java.util.Comparator;
import java.util.List;

import static com.denimgroup.threadfix.CollectionUtils.list;

@Service
@Transactional
public class EventServiceImpl extends AbstractGenericObjectService<Event> implements EventService {

    private final SanitizedLogger log = new SanitizedLogger(EventService.class);

    @Autowired
    private EventDao eventDao;
    @Autowired
    private UserService userService;

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
    public String buildUploadScanString(Scan scan) {
        SimpleDateFormat dateFormatter = new SimpleDateFormat("MMMM d, yyyy h:mm:ss a");

        String uploadScanString = scan.getApplicationChannel().getChannelType().getName() +
                " Scan dated " + dateFormatter.format(scan.getImportTime().getTime()) + " with " + scan.getNumberTotalVulnerabilities() +
                " Vulnerabilities. The scan was uploaded from ";// + scan.getOriginalFileName() + ".";

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
                " Vulnerabilities. The scan was uploaded from ";// + scan.getOriginalFileName();
        if (scanUploadEvent != null) {
            deleteScanString += " on " + dateFormatter.format(scanUploadEvent.getDate());
        }
        deleteScanString += ".";

        return deleteScanString;

    }

    private String getUserName() {
        String userName = "ThreadFix";
        User user = userService.getCurrentUser();
        if (user != null) {
            userName = user.getName();
        }
        return userName;
    }

    @Override
    public List<Event> getUserEvents(User user) {
        List<Event> rawUngroupedUserEvents = eventDao.retrieveUngroupedByUser(user);
        List<Event> rawGroupedUserEvents = eventDao.retrieveGroupedByUser(user);


        List<Event> userEvents = list();

        userEvents.addAll(rawGroupedUserEvents);
        userEvents.addAll(rawUngroupedUserEvents);
        Collections.sort(userEvents, new Comparator<Event>() {
            @Override
            public int compare(Event e1, Event e2) {
                int compared = e1.getDate().compareTo(e2.getDate());
                if (compared != 0) {
                    return compared;
                }
                compared = e1.getEventAction().compareTo(e2.getEventAction());
                if (compared != 0) {
                    return compared;
                }
                int h1 = e1.hashCode();
                int h2 = e2.hashCode();
                if (h1 < h2) {
                    return -1;
                } else if (h1 == h2) {
                    return 0;
                } else {
                    return 1;
                }
            }
        });

        return userEvents;
    }

}
