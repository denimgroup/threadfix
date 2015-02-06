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
import org.junit.Test;

import java.util.List;

import static com.denimgroup.threadfix.service.merge.RemappingTestHarness.getApplicationWith;

/**
 * Created by mcollins on 2/5/15.
 */
public class RemappingTests {

    @Test
    public void testSingleScan() {
        Application application =
                getApplicationWith("1932", "89", "singlescan.ssvl");

        int size = application.getVulnerabilities().size();
        assert size == 1 : "Got " + size + " results instead of 1.";
    }

    @Test
    public void testTwoUnmappedScans() {
        Application application =
                getApplicationWith("1932", "89", "singlescan.ssvl", "singlescan.ssvl");

        int size = application.getVulnerabilities().size();
        assert size == 1 : "Same scan twice yielded " + size + " vulnerabilities, expecting 1.";

        List<Scan> scans = application.getScans();

        Scan scan = application.getVulnerabilities().get(0).getOriginalFinding().getScan();

        assert scan == scans.get(0) : "The original finding was set to the wrong scan.";
    }

    @Test
    public void testTwoScansUnmappedFirst() {
        Application application =
                getApplicationWith("1932", "89", "singlescan.ssvl", "correctSingleVulnScan.ssvl");

        int size = application.getVulnerabilities().size();
        assert size == 1 : "Same scan twice yielded " + size + " vulnerabilities, expecting 1.";

        List<Scan> scans = application.getScans();

        Scan scan = application.getVulnerabilities().get(0).getOriginalFinding().getScan();

        assert scan == scans.get(0) : "The original finding was set to the wrong scan.";
    }

    @Test
    public void testTwoMergingVulnsOneScan() {
        Application application =
                getApplicationWith("1932", "89", "twoMergingVulns.ssvl");

        int size = application.getVulnerabilities().size();
        assert size == 1 : "Same scan twice yielded " + size + " vulnerabilities, expecting 1.";
    }


}
