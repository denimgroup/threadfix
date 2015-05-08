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
package com.denimgroup.threadfix.framework.rails;

import com.denimgroup.threadfix.data.entities.*;
import com.denimgroup.threadfix.framework.TestConstants;
import com.denimgroup.threadfix.importer.ScanLocationManager;
import com.denimgroup.threadfix.importer.merge.Merger;
import com.denimgroup.threadfix.importer.utils.ParserUtils;
import org.junit.Test;

import java.util.List;

/**
 * Created by sgerick on 5/8/2015.
 */
public class EndToEndTests {

    private final String RAILS_ZAP_DYNAMIC = "SBIR/railsgoat_zapscan_dynamic.xml";
    private final String RAILS_CHECKMARX_STATIC = "SBIR/railsgoat_checkmarx_static.xml";

    private final String RAILS_SOURCE_LOCATION = "C:\\SourceCode\\railsgoat-master";


    @Test
    public void assertDynamicScanHasXSS() {
        testHasXSS(RAILS_ZAP_DYNAMIC);
    }

    @Test
    public void assertStaticScanHasXSS() {
        testHasXSS(RAILS_CHECKMARX_STATIC);
    }

    @Test
    public void testXSSVulnsMerge() {
        Application application = Merger.mergeFromDifferentScanners(RAILS_SOURCE_LOCATION,  // TestConstants.RAILS_SOURCE_LOCATION
                                                                    RAILS_ZAP_DYNAMIC,
                                                                    RAILS_CHECKMARX_STATIC);

        List<Scan> scans = application.getScans();
        assert scans.size() == 2 : "Got " + scans.size() + " scans instead of 2.";

        boolean hasMergedXSSVuln = false;
        int countXSS = 0;

        for (Vulnerability vulnerability : application.getVulnerabilities()) {

            if (vulnerability.getFindings().size() > 1) {
                System.out.println("vulnerability = " + vulnerability);
                System.out.println("    vuln.size = " + vulnerability.getFindings().size());
            }

            if (vulnerability.getGenericVulnerability().getDisplayId().equals(79)) {
                countXSS++;

                System.out.println();
                System.out.println(vulnerability.getVulnerabilityName());
                System.out.println(vulnerability.getSurfaceLocation());
                System.out.println(vulnerability.getCalculatedFilePath());
                System.out.println(vulnerability.getCalculatedUrlPath());

                if (vulnerability.getFindings().size() == 2) {
                    hasMergedXSSVuln = true;
                    System.out.println("Found a XSS vuln[" + countXSS + "] with 2 findings!");
                } else {
                    System.out.println("Found a XSS vuln[" + countXSS + "] but it didn't have 2 findings; " +
                            "it had " + vulnerability.getFindings().size() + ".");
                }
            }
        }

        System.err.println("countXSS = " + countXSS );
        System.err.println("hasMergedXSSVuln is " + hasMergedXSSVuln);

        assert hasMergedXSSVuln : "Didn't find a merged vulnerability.";
    }



    private void testHasXSS(String scanLocation) {
        Scan scan = ParserUtils.getScan(scanLocation);
        boolean succeeded = false;
        int countXSS = 0;
        for (Finding finding : scan) {
            Integer genericId = null;

            GenericVulnerability genericVulnerability = finding.getChannelVulnerability().getGenericVulnerability();

            if (genericVulnerability != null) {
                genericId = genericVulnerability.getId();
                System.out.println("genericVulnerability = " + genericVulnerability);
                System.out.println("genericVulnerability.getName() = " + genericVulnerability.getName());
            }

            if (genericId != null && genericId.equals(79)) {
                succeeded = true;
                countXSS++;
            }
        }
        assert succeeded : "Didn't find a 79.";
    }


}
