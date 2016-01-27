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

import com.denimgroup.threadfix.data.entities.Application;
import com.denimgroup.threadfix.data.entities.Finding;
import com.denimgroup.threadfix.data.entities.Vulnerability;
import com.denimgroup.threadfix.importer.ScanLocationManager;
import org.junit.Test;

import static com.denimgroup.threadfix.data.entities.ScannerDatabaseNames.CAT_NET_DB_NAME;
import static com.denimgroup.threadfix.data.entities.ScannerDatabaseNames.CHECKMARX_DB_NAME;
import static com.denimgroup.threadfix.data.entities.ScannerDatabaseNames.FORTIFY_DB_NAME;

/**
 * Created by mcollins on 3/18/15.
 */
public class FindingMatcherTests {

    @Test
    public void testRiskEStaticMerging() {
        Application application = Merger.mergeFromDifferentScanners(null, // no source available
                ScanLocationManager.getRoot() + "Static/CAT.NET/catnet_RiskE.xml",
                ScanLocationManager.getRoot() + "Static/Fortify/ZigguratUtility.fpr");

        boolean hadOneMatch = false;

        for (Vulnerability vulnerability : application.getVulnerabilities()) {
            if (vulnerability.getGenericVulnerability().getDisplayId() == 79 &&
                    vulnerability.getSurfaceLocation().getParameter().equals("txtCardNumber") &&
                    vulnerability.getSurfaceLocation().getPath().endsWith("MakePayment.aspx")) {
                hasBothScanners(vulnerability, CAT_NET_DB_NAME, FORTIFY_DB_NAME);
                hadOneMatch = true;
            }
        }

        assert hadOneMatch : "Didn't find any matches.";
    }

    @Test
    public void testCWE584StaticMerging() {
        Application application = Merger.mergeFromDifferentScanners(null, // no source available
                ScanLocationManager.getRoot() + "Static/Checkmarx/Checkmarx-CWE584.xml",
                ScanLocationManager.getRoot() + "Static/Fortify/Fortify-CWE584.fpr");

        boolean hadOneMatch = false;

        for (Vulnerability vulnerability : application.getVulnerabilities()) {
            if (vulnerability.getGenericVulnerability().getDisplayId() == 584 &&
                    vulnerability.getSurfaceLocation().getPath().contains("CWE584_Return_in_Finally_Block")) {
                hasBothScanners(vulnerability, CHECKMARX_DB_NAME, FORTIFY_DB_NAME);
                hadOneMatch = true;
            }
        }

        assert hadOneMatch : "Didn't find any matches.";
    }

    private void hasBothScanners(Vulnerability vulnerability, String scanner1, String scanner2) {
        boolean hasScanner1 = false, hasScanner2 = false;

        for (Finding finding : vulnerability.getFindings()) {
            if (scanner1.equals(finding.getChannelNameOrNull())) {
                hasScanner1 = true;
            } else if (scanner2.equals(finding.getChannelNameOrNull())) {
                hasScanner2 = true;
            }
        }

        assert hasScanner1 : "Didn't have " + scanner1 + ".";
        assert hasScanner2 : "Didn't have " + scanner2 + ".";
    }


}
