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

import com.denimgroup.threadfix.data.entities.Application;
import com.denimgroup.threadfix.data.entities.Scan;
import com.denimgroup.threadfix.data.entities.ScanCloseVulnerabilityMap;
import com.denimgroup.threadfix.data.entities.ScanReopenVulnerabilityMap;
import org.junit.Test;

import java.util.List;

import static com.denimgroup.threadfix.service.merge.RemappingTestHarness.getApplicationWith;

/**
 * Created by mcollins on 2/5/15.
 */
public class RemappingTests {

    public static final String
            UNMAPPED = "singlescan.ssvl",
            NO_VULNS = "noVulns.ssvl",
            ALREADY_MAPPED = "correctSingleVulnScan.ssvl",
            FROM_ID = "1932",
            TO_ID = "89";

    @Test
    public void testSingleScan() {
        Application application =
                getApplicationWith(UNMAPPED);

        int size = application.getVulnerabilities().size();
        assert size == 1 : "Got " + size + " results instead of 1.";
    }

    @Test
    public void testTwoUnmappedScans() {
        Application application =
                getApplicationWith(UNMAPPED, UNMAPPED);

        testTwoScansOneVuln(application);
    }

    @Test
    public void testTwoScansUnmappedFirst() {
        Application application =
                getApplicationWith(UNMAPPED, ALREADY_MAPPED);

        testTwoScansOneVuln(application, true);
    }

    @Test
    public void testTwoScansUnmappedSecond() {
        Application application =
                getApplicationWith(ALREADY_MAPPED, UNMAPPED);

        testTwoScansOneVuln(application);
    }

    @Test
    public void testClosedAtEndNewVuln() {
        Application application =
                getApplicationWith(UNMAPPED, NO_VULNS);

        testTwoScansOneVuln(application, false);
    }

    @Test
    public void testClosedAtEnd() {
        Application application =
                getApplicationWith(ALREADY_MAPPED, UNMAPPED, NO_VULNS);

        testTwoScansOneVuln(application, false);
    }

    @Test
    public void testReopen() {
        Application application =
                getApplicationWith(ALREADY_MAPPED, NO_VULNS, UNMAPPED);

        testTwoScansOneVuln(application, true);
    }

    @Test
    public void testOpenNewAndClose() {
        Application application =
                getApplicationWith(NO_VULNS, UNMAPPED, NO_VULNS);

        testTwoScansOneVuln(application, false, 1);

        assert application.getScans().get(2).getScanCloseVulnerabilityMaps().size() == 1 :
                "Didn't have a close map.";
    }

    @Test
    public void testCloseMapMoved() {
        Application application =
                getApplicationWith(ALREADY_MAPPED, UNMAPPED, NO_VULNS);

        testTwoScansOneVuln(application, false);

        List<ScanCloseVulnerabilityMap> closeMaps = application.getScans().get(2).getScanCloseVulnerabilityMaps();
        assert closeMaps != null && closeMaps.size() == 1 :
                "Didn't have a close map.";

        List<ScanCloseVulnerabilityMap> maps = application.getScans().get(1).getScanCloseVulnerabilityMaps();
        assert maps == null || maps.size() == 0:
                "Scan 1 had close map.";

    }

    @Test
    public void testReopenMapMoved() {
        Application application =
                getApplicationWith(ALREADY_MAPPED, NO_VULNS, UNMAPPED, ALREADY_MAPPED);

        testTwoScansOneVuln(application);

        List<ScanReopenVulnerabilityMap> closeMaps = application.getScans().get(2).getScanReopenVulnerabilityMaps();
        assert closeMaps != null && closeMaps.size() == 1 :
                "Scan 3 didn't have reopen map.";

        List<ScanReopenVulnerabilityMap> maps = application.getScans().get(3).getScanReopenVulnerabilityMaps();
        assert maps == null || maps.size() == 0:
                "Scan 4 had reopen map.";

    }

    private void testTwoScansOneVuln(Application application) {
        testTwoScansOneVuln(application, true);
    }

    private void testTwoScansOneVuln(Application application, boolean open) {
        testTwoScansOneVuln(application, open, 0);
    }

    private void testTwoScansOneVuln(Application application, boolean open, int scanBelongsTo) {
        int size = application.getVulnerabilities().size();
        assert size == 1 : "Same scan twice yielded " + size + " vulnerabilities, expecting 1.";

        List<Scan> scans = application.getScans();

        Scan scan = application.getVulnerabilities().get(0).getOriginalFinding().getScan();

        assert scan == scans.get(scanBelongsTo) : "The original finding was set to the wrong scan.";

        assert application.getVulnerabilities().get(0).isActive() == open: "Vulnerability status was wrong, expecting open == " + open + ".";
    }

    @Test
    public void testTwoMergingVulnsOneScan() {
        Application application = getApplicationWith("twoMergingVulns.ssvl");

        int size = application.getVulnerabilities().size();
        assert size == 1 : "Same scan twice yielded " + size + " vulnerabilities, expecting 1.";
    }

}
