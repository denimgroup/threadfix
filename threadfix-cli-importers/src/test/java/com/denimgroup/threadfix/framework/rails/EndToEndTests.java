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
import com.denimgroup.threadfix.data.enums.InformationSourceType;
import com.denimgroup.threadfix.data.interfaces.Endpoint;
import com.denimgroup.threadfix.framework.TestConstants;
import com.denimgroup.threadfix.framework.engine.full.EndpointDatabase;
import com.denimgroup.threadfix.framework.engine.full.EndpointDatabaseFactory;
import com.denimgroup.threadfix.framework.engine.full.EndpointQuery;
import com.denimgroup.threadfix.framework.engine.full.EndpointQueryBuilder;
import com.denimgroup.threadfix.importer.utils.ParserUtils;
import com.denimgroup.threadfix.service.merge.Merger;
import org.junit.Test;

import java.util.List;

import static com.denimgroup.threadfix.importer.ScanLocationManager.getRoot;

/**
 * Created by sgerick on 5/8/2015.
 */
public class EndToEndTests {

    private final String RAILS_ZAP_DYNAMIC = "SBIR/railsgoat_zapscan.xml";
    private final String RAILS_CHECKMARX_STATIC = "SBIR/railsgoat_checkmarx.xml";
    private final String RAILS_BURP_DYNAMIC = "SBIR/railsgoat_burpscan.xml";
    private final String RAILS_BRAKEMAN_STATIC = "SBIR/railsgoat_brakeman.json";

    @Test
    public void assertDynamicScanHasXSS() {
        testHasXSS(RAILS_ZAP_DYNAMIC);
    }

    @Test
    public void assertStaticScanHasXSS() {
        testHasXSS(RAILS_CHECKMARX_STATIC);
    }

    @Test
    public void testBurpBrake() {
        testHasXSS(RAILS_BURP_DYNAMIC);
        testHasXSS(RAILS_BRAKEMAN_STATIC);
    }

    @Test
    public void testStaticFindingMatchesEndpoint() {
        EndpointDatabase database = EndpointDatabaseFactory.getDatabase(TestConstants.RAILSGOAT_SOURCE_LOCATION);

        EndpointQuery query = EndpointQueryBuilder.start()
                .setInformationSourceType(InformationSourceType.STATIC)
                .setStaticPath("railsgoat/app/controllers/password_resets_controller.rb")
                .generateQuery();

        Endpoint match = database.findBestMatch(query);

        assert match != null : "Didn't find match for file password_resets_controller.rb";
    }

    @Test
    public void testDynamicFindingMatchesEndpoint() {
        EndpointDatabase database = EndpointDatabaseFactory.getDatabase(TestConstants.RAILSGOAT_SOURCE_LOCATION);

        EndpointQuery query = EndpointQueryBuilder.start()
                .setDynamicPath("/forgot_password")
                .generateQuery();

        Endpoint match = database.findBestMatch(query);

        assert match != null : "Didn't find match for url /forgot_password";
    }

    @Test
    public void testFindingsMatchEndpoint() {
        EndpointDatabase database = EndpointDatabaseFactory.getDatabase(TestConstants.RAILSGOAT_SOURCE_LOCATION);

        EndpointQuery staticQuery = EndpointQueryBuilder.start()
                .setInformationSourceType(InformationSourceType.STATIC)
                .setStaticPath("railsgoat/app/controllers/password_resets_controller.rb")
                .setParameter("email")
                .generateQuery();

        Endpoint staticMatch = database.findBestMatch(staticQuery);

        EndpointQuery dynamicQuery = EndpointQueryBuilder.start()
                .setDynamicPath("/forgot_password")
                .generateQuery();

        Endpoint dynamicMatch = database.findBestMatch(dynamicQuery);

        assert staticMatch != null : "Didn't find match for file password_resets_controller.rb";
        assert dynamicMatch != null : "Didn't find match for url /forgot_password";

    }

    @Test
    public void testStaticStaticMerge() {
        Application application = Merger.mergeFromDifferentScanners(TestConstants.RAILSGOAT_SOURCE_LOCATION,
                getRoot() + RAILS_BRAKEMAN_STATIC,
                getRoot() + RAILS_CHECKMARX_STATIC);

        List<Scan> scans = application.getScans();
        assert scans.size() == 2 : "Got " + scans.size() + " scans instead of 2.";

        boolean hasMergedVuln = false;
        int countXSS = 0;

        for (Vulnerability vulnerability : application.getVulnerabilities()) {

            if (vulnerability.getFindings().size() > 1) {
                hasMergedVuln = true;
                System.out.println("vulnerability = " + vulnerability);
                System.out.println(" # of finding = " + vulnerability.getFindings().size());
            }
        }

        assert hasMergedVuln : "Didn't find a merged vulnerability.";
    }

    @Test
    public void testXSSVulnsMerge() {
        Application application = Merger.mergeFromDifferentScanners(TestConstants.RAILSGOAT_SOURCE_LOCATION,
                                                                    getRoot() + RAILS_ZAP_DYNAMIC,
                                                                    getRoot() + RAILS_CHECKMARX_STATIC);

        List<Scan> scans = application.getScans();
        assert scans.size() == 2 : "Got " + scans.size() + " scans instead of 2.";

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

        assert hasMergedXSSVuln : "Didn't find a merged vulnerability.";
    }



    private void testHasXSS(String scanLocation) {
        Scan scan = ParserUtils.getScan(scanLocation);
        boolean succeeded = false;
        int countXSS = 0;
        for (Finding finding : scan) {
            Integer genericId = null;

            System.out.println(finding);

            GenericVulnerability genericVulnerability = finding.getChannelVulnerability().getGenericVulnerability();

            if (genericVulnerability != null) {
                genericId = genericVulnerability.getId();
            }

            if (genericId != null && genericId.equals(79)) {
                succeeded = true;
                countXSS++;
            }
        }
        assert succeeded : "Didn't find a 79.";
    }


}
