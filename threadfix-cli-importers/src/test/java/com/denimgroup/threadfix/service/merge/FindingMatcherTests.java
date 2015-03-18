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
import com.denimgroup.threadfix.data.entities.Finding;
import com.denimgroup.threadfix.data.entities.Vulnerability;
import com.denimgroup.threadfix.importer.ScanLocationManager;
import org.junit.Test;

import static com.denimgroup.threadfix.data.entities.ScannerDatabaseNames.CAT_NET_DB_NAME;
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
                boolean hasFortify = false, hasCatNet = false;

                for (Finding finding : vulnerability.getFindings()) {
                    if (FORTIFY_DB_NAME.equals(finding.getChannelNameOrNull())) {
                        hasFortify = true;
                    } else if (CAT_NET_DB_NAME.equals(finding.getChannelNameOrNull())) {
                        hasCatNet = true;
                    }
                }

                assert hasFortify : "Didn't have Fortify.";
                assert hasCatNet : "Didn't have cat.net.";
                hadOneMatch = true;
            }
        }

        assert hadOneMatch : "Didn't find any matches.";
    }


}
