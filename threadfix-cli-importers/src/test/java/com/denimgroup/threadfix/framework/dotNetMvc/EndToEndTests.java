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
package com.denimgroup.threadfix.framework.dotNetMvc;

import com.denimgroup.threadfix.data.entities.Finding;
import com.denimgroup.threadfix.data.entities.Scan;
import com.denimgroup.threadfix.data.interfaces.Endpoint;
import com.denimgroup.threadfix.framework.engine.ThreadFixInterface;
import com.denimgroup.threadfix.framework.engine.full.EndpointDatabase;
import com.denimgroup.threadfix.importer.utils.ParserUtils;
import org.junit.Test;

import java.util.Set;

import static com.denimgroup.threadfix.framework.impl.dotNet.ContosoUtilities.getContosoEndpointDatabase;

/**
 * Created by mac on 8/18/14.
 */
public class EndToEndTests {

    @Test
    public void testDynamicScanHasXSSVuln() {
        Scan scan = ParserUtils.getScan("SBIR/contoso.xml");

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
    public void testDynamicDatabaseLookups() {
        Scan scan = ParserUtils.getScan("SBIR/contoso.xml");

        EndpointDatabase database = getContosoEndpointDatabase(scan);

        assert database != null : "Database was null, can't continue";

        boolean succeededStudent = false, succeededCreate = false;

        for (Finding finding : scan) {
            Integer genericId = finding.getChannelVulnerability().getGenericVulnerability().getId();
            if (genericId != null && genericId.equals(79)) {
                Set<Endpoint> endpointList = database.findAllMatches(ThreadFixInterface.toEndpointQuery(finding));
                if (!endpointList.isEmpty()) {
                    String path = finding.getSurfaceLocation().getPath();
                    if (path.equals("/contoso/Student/Create")) {
                        for (Endpoint endpoint : endpointList) {
                            if (endpoint.getFilePath().endsWith("StudentController.cs")) {
                                succeededCreate = true;
                            }
                        }
                    } else if (path.equals("/contoso/Student")) {
                        for (Endpoint endpoint : endpointList) {
                            if (endpoint.getFilePath().endsWith("StudentController.cs")) {
                                succeededStudent = true;
                            }
                        }
                    }
                }
            } else {
                System.out.println("Got " + genericId);
            }
        }

        assert succeededCreate : "Didn't find /Student/Create.";
        assert succeededStudent : "Didn't find /Student.";
    }

}
