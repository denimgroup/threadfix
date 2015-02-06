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
package com.denimgroup.threadfix.service.merge;

/**
 * Created by mcollins on 2/5/15.
 */

import com.denimgroup.threadfix.data.dao.ApplicationChannelDao;
import com.denimgroup.threadfix.data.dao.ApplicationDao;
import com.denimgroup.threadfix.data.dao.FindingDao;
import com.denimgroup.threadfix.data.dao.VulnerabilityDao;
import com.denimgroup.threadfix.data.entities.*;
import com.denimgroup.threadfix.logging.SanitizedLogger;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.util.Calendar;
import java.util.List;

import static com.denimgroup.threadfix.CollectionUtils.list;

@Component
public class RemappingService {

    SanitizedLogger LOG = new SanitizedLogger(RemappingService.class);

    @Autowired
    ApplicationDao applicationDao;
    @Autowired
    FindingDao findingDao;
    @Autowired
    ApplicationChannelDao applicationChannelDao;
    @Autowired
    VulnerabilityDao vulnerabilityDao;

    public void remapFindings(ChannelVulnerability vulnerability) {
        List<Application> applications = applicationDao.retrieveAllActive();

        for (Application application : applications) {
            remapFindings(application, vulnerability);
        }
    }

    private void remapFindings(Application application, ChannelVulnerability type) {

        Integer id = type.getId();

        ApplicationChannel channel = applicationChannelDao.retrieveByAppIdAndChannelId(application.getId(), id);

        VulnerabilityCache
                cache = new VulnerabilityCache(application.getVulnerabilities()),
                newCache = new VulnerabilityCache();

        List<Vulnerability> newVulnerabilities = list();

        List<Finding> findings = findingDao.retrieveByChannelVulnerability(id);

        LOG.info("Got " + findings.size() + " results for this channel vulnerability.");

        for (Finding finding : findings) {

            attemptToAddFromCache(cache, finding);
            attemptToAddFromCache(newCache, finding);

            if (finding.getVulnerability() == null) {
                Vulnerability parse = VulnerabilityParser.parse(finding);

                newVulnerabilities.add(parse);
                newCache.add(parse);
            }

        }

        for (Vulnerability newVulnerability : newVulnerabilities) {
            application.addVulnerability(newVulnerability);
            fixStateAndMappings(channel, type, newVulnerability);
            vulnerabilityDao.saveOrUpdate(newVulnerability);
        }
    }

    enum Event {
        OLD_FINDING, NEW_FINDING, CLOSE, REOPEN
    }

    private void fixStateAndMappings(ApplicationChannel channel,
                                     ChannelVulnerability channelVulnerability,
                                     Vulnerability newVulnerability) {
        setFirstFindingForVuln(newVulnerability);

//
//        Map<Calendar, Event> scannerEventMap = getScannerEventMap(channelVulnerability, newVulnerability);
//
//        List<Calendar> dates = listFrom(scannerEventMap.keySet());
//
//        Collections.sort(dates);
//
//        boolean first = true;
//
//        for (Calendar date : dates) {
//
//        }



    }

    // there has to be a better algorithm for this
    // or maybe we can sidestep by setting this in a different spot?
    private void setFirstFindingForVuln(Vulnerability newVulnerability) {
        if (newVulnerability.getFindings().size() == 0) {
            return;
        }


        Finding currentOriginalFinding = null;
        Finding oldestFinding = null;
        Calendar oldestDate = null;

        for (Finding finding : newVulnerability.getFindings()) {
            if (oldestDate == null || finding.getScan().getImportTime().before(oldestDate)) {
                oldestDate = finding.getScan().getImportTime();
                oldestFinding = finding;
            }

            if (finding.isFirstFindingForVuln()) {
                currentOriginalFinding = finding;
            }
        }

        if (currentOriginalFinding != oldestFinding) {
            if (currentOriginalFinding != null) {
                currentOriginalFinding.setFirstFindingForVuln(false);
            }

            oldestFinding.setFirstFindingForVuln(true);
        }
    }

//    private Map<Calendar, Event> getScannerEventMap(ChannelVulnerability channelVulnerability, Vulnerability newVulnerability) {
//        Map<Calendar, Event> scannerEvents = newMap();
//
//        for (Finding finding : newVulnerability.getFindings()) {
//            if (finding.getChannelVulnerability().equals(channelVulnerability)) {
//                scannerEvents.put(finding.getScannedDate(), Event.NEW_FINDING);
//            } else {
//                scannerEvents.put(finding.getScannedDate(), Event.OLD_FINDING);
//            }
//        }
//
//        for (ScanCloseVulnerabilityMap closeMap : newVulnerability.getScanCloseVulnerabilityMaps()) {
//            scannerEvents.put(closeMap.getScan().getImportTime(), Event.CLOSE);
//        }
//
//        for (ScanReopenVulnerabilityMap reopenMap : newVulnerability.getScanReopenVulnerabilityMaps()) {
//            scannerEvents.put(reopenMap.getScan().getImportTime(), Event.REOPEN);
//        }
//
//        return scannerEvents;
//    }

    private void attemptToAddFromCache(VulnerabilityCache cache, Finding finding) {
        Iterable<Vulnerability> possibilities = cache.getPossibilities(finding);

        if (possibilities.iterator().hasNext()) { // not empty

            FindingMatcher findingMatcher = new FindingMatcher(finding.getScan());

            for (Vulnerability vulnerability : possibilities) {

                if (findingMatcher.doesMatch(finding, vulnerability)) {
                    VulnerabilityParser.addToVuln(vulnerability, finding);
                }
            }
        }
    }
}
