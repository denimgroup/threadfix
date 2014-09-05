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
package com.denimgroup.threadfix.framework.dotNetWebForm;

import com.denimgroup.threadfix.data.entities.Application;
import com.denimgroup.threadfix.data.entities.Finding;
import com.denimgroup.threadfix.data.entities.Scan;
import com.denimgroup.threadfix.data.entities.Vulnerability;
import com.denimgroup.threadfix.data.interfaces.Endpoint;
import com.denimgroup.threadfix.framework.TestConstants;
import com.denimgroup.threadfix.framework.engine.ThreadFixInterface;
import com.denimgroup.threadfix.framework.engine.full.EndpointDatabase;
import com.denimgroup.threadfix.importer.merge.Merger;
import com.denimgroup.threadfix.importer.utils.ParserUtils;
import org.junit.Test;

import java.util.List;
import java.util.Set;

import static com.denimgroup.threadfix.framework.impl.dotNetWebForm.WebFormUtilities.getWebFormDatabase;

/**
 * Created by mac on 9/5/14.
 */
public class EndToEndTests {

    @Test
    public void assertDynamicScanHasXSS() {
        testHasXSS(ParserUtils.getScan("SBIR/webform.xml"));
    }

    @Test
    public void assertStaticScanHasXSS() {
        testHasXSS(ParserUtils.getScan("SBIR/webform.fpr"));
    }

    private void testHasXSS(Scan scan) {
        boolean succeeded = false;

        for (Finding finding : scan) {
            Integer genericId = finding.getChannelVulnerability().getGenericVulnerability().getId();
            if (genericId != null && genericId.equals(79)) {
                succeeded = true;
                System.out.println("Got it");
            } else {
                System.out.println("Got " + genericId);
            }
        }

        assert succeeded : "Didn't find 79.";
    }

    @Test
    public void assertDynamicXSSFindsEndpoint() {
        Scan scan = ParserUtils.getScan("SBIR/webform.xml");

        EndpointDatabase database = getWebFormDatabase(scan);

        assert database != null : "Database was null, can't continue";

        boolean foundBasicEndpoint = false;

        for (Finding finding : scan) {
            Integer genericId = finding.getChannelVulnerability().getGenericVulnerability().getId();
            if (genericId != null && genericId.equals(79)) {
                Set<Endpoint> endpointList = database.findAllMatches(ThreadFixInterface.toEndpointQuery(finding));
                if (!endpointList.isEmpty()) {
                    String path = finding.getSurfaceLocation().getPath();
                    if (path.endsWith("/WebForm1.aspx")) {
                        for (Endpoint endpoint : endpointList) {
                            if (endpoint.getFilePath().endsWith("WebForm1.aspx.cs")) {
                                foundBasicEndpoint = true;
                            }
                        }
                    }
                }
            } else {
                System.out.println("Got " + genericId);
            }
        }

        assert foundBasicEndpoint : "Didn't find /WebForm1.aspx";
    }

    @Test
    public void testXSSVulnsMerge() {
        Application application = Merger.mergeFromDifferentScanners(TestConstants.WEB_FORMS_ROOT,
                "SBIR/webform.xml", "SBIR/webform.fpr");

        List<Scan> scans = application.getScans();
        assert scans.size() == 2 :
                "Got " + scans.size() + " scans instead of 2.";

        boolean hasMergedXSSVuln = false;

        for (Vulnerability vulnerability : application.getVulnerabilities()) {
            if (vulnerability.getGenericVulnerability().getDisplayId().equals(79)) {
                if (vulnerability.getFindings().size() == 2) {
                    hasMergedXSSVuln = true;
                    System.out.println("Found it!");
                } else {
                    System.out.println("Found a XSS vuln but it didn't have 2 findings. " +
                            "It had " + vulnerability.getFindings().size());
                }
            }
        }

        assert hasMergedXSSVuln : "Didn't find a merged vulnerability.";
    }

}
