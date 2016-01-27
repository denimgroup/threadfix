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
package com.denimgroup.threadfix.service.merge;

import com.denimgroup.threadfix.data.entities.*;
import com.denimgroup.threadfix.logging.SanitizedLogger;
import com.denimgroup.threadfix.service.VulnerabilityService;
import com.denimgroup.threadfix.service.VulnerabilityStatusService;
import org.springframework.beans.factory.annotation.Autowired;

import java.util.*;

import static com.denimgroup.threadfix.CollectionUtils.*;

public class ChannelMerger {

    private static final SanitizedLogger LOG = new SanitizedLogger(ChannelMerger.class);

    @Autowired
    private VulnerabilityService vulnerabilityService;
    @Autowired
    private VulnerabilityStatusService vulnerabilityStatusService;

    private Scan scan;
    private ApplicationChannel applicationChannel;
    private DefaultConfiguration defaultConfiguration;

    List<Finding> newFindings = list();
    Map<String, Vulnerability> oldNativeIdVulnHash = map();
    Map<String, Finding> oldNativeIdFindingHash = map();
    Set<Integer> alreadySeenVulnIds = new TreeSet<Integer>();
    Integer closed = 0, resurfaced = 0, total = 0, numberNew = 0, old = 0,
            numberRepeatResults = 0, numberRepeatFindings = 0, oldVulnerabilitiesInitiallyFromThisChannel = 0;
    Map<String, Finding> scanHash;
    List<Scan> otherFoundScans = list();

    /**
     * This is the first round of scan merge that only considers scans from the same scanner
     * as the incoming scan.
     *
     */
    public static void channelMerge(VulnerabilityService vulnerabilityService,
                                    VulnerabilityStatusService vulnerabilityStatusService,
                                    Scan scan,
                                    ApplicationChannel applicationChannel,
                                    DefaultConfiguration defaultConfiguration) {
        if (scan == null || applicationChannel == null) {
            LOG.warn("Insufficient data to complete Application Channel-wide merging process.");
            return;
        }

        ChannelMerger merger = new ChannelMerger();

        merger.scan = scan;
        merger.applicationChannel = applicationChannel;
        merger.vulnerabilityService = vulnerabilityService;
        merger.vulnerabilityStatusService = vulnerabilityStatusService;
        merger.defaultConfiguration = defaultConfiguration;

        merger.performMerge();
    }

    private void performMerge() {
        assert vulnerabilityService != null : "vulnerabilityService was null. Spring autowiring failed, fix the code.";

        if (scan.getFindings() == null) {
            scan.setFindings(listOf(Finding.class));
        }

        for (Finding finding : scan.getFindings()) {
            finding.setScan(scan);
        }

        LOG.info("Starting Application Channel-wide merging process with "
                + scan.getFindings().size() + " findings.");

        scanHash = createNativeIdFindingMap(scan);

        LOG.info("After filtering out duplicate native IDs, there are "
                + scanHash.keySet().size() + " findings.");

        // initializes data structures for the second part
        constructOldFindingMaps();

        mergeFindings();

        closeMissingVulnerabilities();

        LOG.info("Merged " + old + " Findings to old findings by native ID.");
        LOG.info("Closed " + closed + " old vulnerabilities.");
        LOG.info(numberRepeatResults
                + " results were repeats from earlier scans and were not included in this scan.");
        LOG.info(resurfaced + " vulnerabilities resurfaced in this scan.");
        LOG.info("Scan completed channel merge with " + numberNew
                + " new Findings.");

        scan.setNumberNewVulnerabilities(numberNew);
        scan.setNumberOldVulnerabilities(old);
        scan.setNumberTotalVulnerabilities(total);
        scan.setNumberClosedVulnerabilities(closed);
        scan.setNumberResurfacedVulnerabilities(resurfaced);
        scan.setNumberRepeatResults(numberRepeatResults);
        scan.setNumberRepeatFindings(numberRepeatFindings);
        scan.setNumberOldVulnerabilitiesInitiallyFromThisChannel(oldVulnerabilitiesInitiallyFromThisChannel);

        scan.setFindings(newFindings);
    }

    private void closeMissingVulnerabilities() {
        FindingMatcher matcher = new FindingMatcher(null);

        if (scan.getApplicationChannel() == null || scan.getApplicationChannel().getChannelType() == null) {
            throw new IllegalStateException("Got a null application channel or channel type.");
        }

        // for every old native ID
        String name = scan.getApplicationChannel().getChannelType().getName();
        // Immediately close
        boolean closeVulnWhenNoScannersReport = defaultConfiguration.getCloseVulnWhenNoScannersReport();

        for (Map.Entry<String, Vulnerability> entry : oldNativeIdVulnHash.entrySet()) {
            otherFoundScans = list();
            String nativeId = entry.getKey();
            Vulnerability vulnerability = entry.getValue();

            // if the old ID is not present in the new scan and the vulnerabilty is open, close it
            if (!scanHash.containsKey(nativeId) && vulnerability != null && vulnerability.isActive()) {

                // we need to make sure ALL the findings are closed now
                boolean shouldClose = true;
                for (Finding finding : vulnerability.getFindings()) {

                    // if the finding is contained in the new scan, it's not closed
                    if (scanHash.containsKey(finding.getNativeId())) {
                        shouldClose = false;
                        break;
                    }

                    // if the finding is from another channel, then check system setting and if it was closed in that channel
                    if (!name.equals(finding.getChannelNameOrNull())) {

                        List<String> otherFindingNativeIds = constructLatestScanNativeIds(finding);
                        if (otherFindingNativeIds.contains(finding.getNativeId())) { // still present in other scanner
                            if (closeVulnWhenNoScannersReport) {
                                shouldClose = false;
                                break;
                            }
                        }
                    }
                }

                if (shouldClose) {
                    // Check if new scan contains finding with same generic vulnerability and surface location with this old vulnerability
                    for (Finding newScanFinding : scan.getFindings()) {
                        if (matcher.doesMatch(newScanFinding, vulnerability)) {
                            shouldClose = false;
                            break;
                        }
                    }
                }

                if (!shouldClose) {
                    continue; // this skips to the next entry
                }

                if (scan.getImportTime() != null) {
                    vulnerabilityStatusService.closeVulnerability(vulnerability, scan,
                            scan.getImportTime(), false, false);
                } else {
                    vulnerabilityStatusService.closeVulnerability(vulnerability, scan,
                            Calendar.getInstance(), false, false);
                }

                vulnerabilityStatusService.createCloseVulnMaps(vulnerability, otherFoundScans);

                vulnerabilityService.storeVulnerability(vulnerability);

                closed += 1;
            }
        }
    }

    // for each native ID in the new scan
    private void mergeFindings() {
        for (String nativeId : scanHash.keySet()) {

            // if it's an old finding
            if (oldNativeIdFindingHash.containsKey(nativeId)) {
                createRepeatFindingMap(nativeId);

                // if it's an old finding and we haven't seen the vulnerability before,
                // update the old vulnerability count
                if (oldNativeIdVulnHash.get(nativeId) != null
                        && !alreadySeenVulnIds.contains(oldNativeIdVulnHash.get(
                        nativeId).getId())) {
                    processOldVulnerability(nativeId);
                }

            } else {

                // Otherwise add to the new count and list of new findings
                if (!oldNativeIdFindingHash.containsKey(nativeId)) {
                    numberNew += 1;
                    total += 1;
                    newFindings.add(scanHash.get(nativeId));
                }
            }
        }
    }

    private void processOldVulnerability(String nativeId) {
        Vulnerability vulnerability = oldNativeIdVulnHash.get(nativeId);
        alreadySeenVulnIds.add(vulnerability.getId());

        if (applicationChannel.getId() != null
                && vulnerability.getOriginalFinding() != null
                && vulnerability.getOriginalFinding().getScan() != null
                && vulnerability.getOriginalFinding().getScan()
                .getApplicationChannel() != null
                && applicationChannel.getId().equals(
                vulnerability.getOriginalFinding().getScan()
                        .getApplicationChannel().getId())) {
            oldVulnerabilitiesInitiallyFromThisChannel += 1;
        }

        old += 1;
        total += 1;

        if (!vulnerability.isActive()) {
            resurfaced += 1;
            vulnerabilityStatusService.reopenVulnerability(vulnerability, scan,
                    scan.getImportTime());
            vulnerabilityService.storeVulnerability(vulnerability);
        }
    }

    private void createRepeatFindingMap(String nativeId) {
        Finding oldFinding = oldNativeIdFindingHash.get(nativeId),
                newFinding = scanHash.get(nativeId);

        // Set Found HAM Endpoint flag
        if (newFinding.getFoundHAMEndpoint()) {
            oldFinding.setCalculatedFilePath(newFinding.getCalculatedFilePath());
            oldFinding.setFoundHAMEndpoint(newFinding.getFoundHAMEndpoint());
            oldFinding.getVulnerability().setFoundHAMEndpoint(newFinding.getFoundHAMEndpoint());
        }
        // If the finding has been newly marked a false positive, update
        // the existing finding / vuln
        if (newFinding.isMarkedFalsePositive()
                && !oldFinding.isMarkedFalsePositive()) {
            LOG.info("A previously imported finding (" + oldFinding.getNativeId()
                    + ") has been marked a false positive "
                    + "in the scan results. Marking the finding and Vulnerability.");
            oldFinding.setMarkedFalsePositive(true);
            if (oldFinding.getVulnerability() != null) {
                vulnerabilityStatusService.markVulnerabilityFalsePositive(oldFinding.getVulnerability(), newFinding.getScan(), false, false);
                vulnerabilityService.storeVulnerability(oldFinding.getVulnerability());
            }
        }
        // If the finding has had its false positive status removed, update
        // the existing finding / vuln
        else if (oldFinding.isMarkedFalsePositive()
                && !newFinding.isMarkedFalsePositive()) {
            LOG.info("A previously imported finding (" + oldFinding.getNativeId()
                    + ") has been marked not a false positive "
                    + "in the scan results. Unmarking the finding and Vulnerability.");
            oldFinding.setMarkedFalsePositive(false);
            if (oldFinding.getVulnerability() != null) {
                vulnerabilityStatusService.unmarkVulnerabilityFalsePositive(oldFinding.getVulnerability(), newFinding.getScan(), false, false);
                vulnerabilityService.storeVulnerability(oldFinding.getVulnerability());
            }
        }

        numberRepeatFindings += 1;
        numberRepeatResults += newFinding.getNumberMergedResults();
        // add it to the old finding maps so that we can know that it
        // was here later
        // the constructor maps everything correctly
        new ScanRepeatFindingMap(oldFinding, scan);
    }

    private void constructOldFindingMaps() {

        // Construct a hash of native ID -> Finding and native ID -> Vulnerability
        for (Finding finding : getOldFindingList(applicationChannel)) {
            if (finding != null && finding.getNativeId() != null
                    && !finding.getNativeId().isEmpty()) {

                String key = finding.getNativeId();

                oldNativeIdVulnHash.put(key, finding.getVulnerability());
                oldNativeIdFindingHash.put(key, finding);
            }
        }
    }

    private List<String> constructLatestScanNativeIds(Finding finding) {
        List<String> result = list();

        if (finding.getScan() == null ||
                finding.getScan().getApplicationChannel() == null
                || finding.getScan().getApplicationChannel().getScanList() == null
                || finding.getScan().getApplicationChannel().getScanList().size() == 0)
            return result;

        Scan latestScan = finding.getScan().getApplicationChannel().getLatestScan();

        if (latestScan != null && latestScan.getId() != null) {

            otherFoundScans.add(latestScan);

            for (Finding otherFinding : latestScan.getFindings()) {
                if (otherFinding != null && otherFinding.getNativeId() != null
                        && !otherFinding.getNativeId().isEmpty()) {
                    result.add(otherFinding.getNativeId());
                }
            }
        }
        return result;
    }

    private List<Finding> getOldFindingList(ApplicationChannel applicationChannel) {
        List<Finding> oldFindings = list();

        // Construct a list of all of the channel's Finding objects
        if (applicationChannel.getScanList() != null) {
            for (Scan oldScan : applicationChannel.getScanList()) {
                if (oldScan != null && oldScan.getId() != null
                        && oldScan.getFindings() != null
                        && oldScan.getFindings().size() != 0) {
                    oldFindings.addAll(oldScan.getFindings());
                }
            }
        }

        return oldFindings;
    }

    private Map<String, Finding> createNativeIdFindingMap(Scan scan) {

        Map<String, Finding> scanHash = map();

        // Construct a hash of native ID -> finding
        for (Finding finding : scan.getFindings()) {
            if (finding != null && finding.getNativeId() != null
                    && !finding.getNativeId().isEmpty()) {

                String key = finding.getNativeId();

                if (scanHash.containsKey(key)) {
                    // Increment the merged results counter in the finding
                    // object in the hash
                    Finding targetFinding = scanHash.get(key);
                    targetFinding.setNumberMergedResults(
                            targetFinding.getNumberMergedResults() + 1);
                } else {
                    scanHash.put(key, finding);
                }
            }
        }

        return scanHash;
    }
}
