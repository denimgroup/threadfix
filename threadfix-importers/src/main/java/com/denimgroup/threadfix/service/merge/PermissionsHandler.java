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

import com.denimgroup.threadfix.data.entities.EndpointPermission;
import com.denimgroup.threadfix.data.entities.Finding;
import com.denimgroup.threadfix.data.entities.Scan;
import com.denimgroup.threadfix.data.entities.Vulnerability;
import com.denimgroup.threadfix.service.EndpointPermissionService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;

import static com.denimgroup.threadfix.CollectionUtils.list;
import static com.denimgroup.threadfix.CollectionUtils.set;
import static com.denimgroup.threadfix.data.entities.AuthenticationRequired.UNKNOWN;

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

            Vulnerability vulnerability = finding.getVulnerability();
            if (vulnerability != null && !seenIds.contains(vulnerability)) {
                seenIds.add(vulnerability);

                vulnerability.setEndpointPermissions(new ArrayList<EndpointPermission>());

                List<EndpointPermission> toAdd = list();

                for (EndpointPermission endpointPermission : finding.getEndpointPermissions()) {
                    if (!vulnerability.getEndpointPermissions().contains(endpointPermission)) {
                        toAdd.add(endpointPermission);
                    }
                }

                for (EndpointPermission endpointPermission : toAdd) {
                    endpointPermission.getVulnerabilityList().add(vulnerability);
                    vulnerability.getEndpointPermissions().add(endpointPermission);
                    endpointPermissionService.saveOrUpdate(endpointPermission);
                }
            }

            if (vulnerability != null && vulnerability.getAuthenticationRequired() == UNKNOWN) {
                vulnerability.setAuthenticationRequired(finding.getAuthenticationRequired());
            }

        }
    }


}
