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

import com.denimgroup.threadfix.data.entities.EndpointPermission;
import com.denimgroup.threadfix.data.entities.Finding;
import com.denimgroup.threadfix.data.entities.Scan;
import com.denimgroup.threadfix.data.entities.Vulnerability;
import com.denimgroup.threadfix.service.EndpointPermissionService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.Set;

import static com.denimgroup.threadfix.CollectionUtils.set;

/**
 * Created by mcollins on 3/31/15.
 */
@Service
public class PermissionsHandler {

    @Autowired
    private EndpointPermissionService endpointPermissionService;

    public void setPermissions(Scan scan, Integer applicationId) {

        Set<Vulnerability> seenIds = set();

        for (Finding finding : scan) {
            endpointPermissionService.addToFinding(finding, applicationId, finding.getRawPermissions());

            if (finding.getVulnerability() != null && !seenIds.contains(finding.getVulnerability())) {
                seenIds.add(finding.getVulnerability());

                finding.getVulnerability().setEndpointPermissions(new ArrayList<EndpointPermission>());

                for (Finding vulnFinding : finding.getVulnerability().getFindings()) {

                    finding.getVulnerability().addPermissions(vulnFinding.getEndpointPermissions());

                }
            }
        }
    }


}
