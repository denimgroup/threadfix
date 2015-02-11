////////////////////////////////////////////////////////////////////////
//
//     Copyright (c) 2009-2014 Denim Group, Ltd.
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
package com.denimgroup.threadfix.framework.struts;

import com.denimgroup.threadfix.data.entities.*;
import com.denimgroup.threadfix.framework.TestConstants;
import com.denimgroup.threadfix.importer.ScanLocationManager;
import com.denimgroup.threadfix.importer.utils.ParserUtils;
import com.denimgroup.threadfix.service.merge.Merger;
import org.junit.Test;

import java.util.List;

/**
 * Created by sgerick on 12/19/14.
 */
public class EndToEndTests {

    @Test
    public void assertDynamicScanHasXSS() {
        testHasXSS(ParserUtils.getScan("SBIR/roller.xml"));
    }

    @Test
    public void assertStaticScanHasXSS() {
        testHasXSS(ParserUtils.getScan("SBIR/roller.fpr"));
    }

    private void testHasXSS(Scan scan) {
        boolean succeeded = false;
        int countXSS = 0;
        for (Finding finding : scan) {
//            Integer genericId = finding.getChannelVulnerability().getGenericVulnerability().getId();
            Integer genericId = null;

            GenericVulnerability genericVulnerability = finding.getChannelVulnerability().getGenericVulnerability();

            if (genericVulnerability != null)
                genericId = genericVulnerability.getId();

            if (genericId != null && genericId.equals(79)) {
                succeeded = true;
                countXSS++;
            }
        }
        assert succeeded : "Didn't find a 79.";
    }

    @Test
    public void testXSSVulnsMerge() {
        Application application = Merger.mergeFromDifferentScanners(TestConstants.ROLLER_SOURCE_LOCATION,
                ScanLocationManager.getRoot() + "SBIR/roller.xml",
                ScanLocationManager.getRoot() + "SBIR/roller.fpr");

        List<Scan> scans = application.getScans();
        assert scans.size() == 2 :
                "Got " + scans.size() + " scans instead of 2.";

        //  System.err.println("app.getVulns.size = " + application.getVulnerabilities().size() );

        boolean hasMergedXSSVuln = false;
        int countXSS = 0;

        for (Vulnerability vulnerability : application.getVulnerabilities()) {
            if (vulnerability.getGenericVulnerability().getDisplayId().equals(79)) {
                countXSS++;
                if (vulnerability.getFindings().size() == 2) {
                    hasMergedXSSVuln = true;
                    System.out.println("Found a XSS vuln[" + countXSS + "] with 2 findings!");
                } else {
                    System.out.println("Found a XSS vuln[" + countXSS + "] but it didn't have 2 findings; " +
                            "it had " + vulnerability.getFindings().size() + ".");
                }
            }
        }

        //  System.err.println("countXSS = " + countXSS );

        assert hasMergedXSSVuln : "Didn't find a merged vulnerability.";
        //  System.err.println("hasMergedXSSVuln is " + hasMergedXSSVuln);

    }

}
