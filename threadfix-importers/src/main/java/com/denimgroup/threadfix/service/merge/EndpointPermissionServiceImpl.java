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

import com.denimgroup.threadfix.data.dao.ApplicationDao;
import com.denimgroup.threadfix.data.dao.EndpointPermissionDao;
import com.denimgroup.threadfix.data.dao.FindingDao;
import com.denimgroup.threadfix.data.dao.GenericNamedObjectDao;
import com.denimgroup.threadfix.data.entities.EndpointPermission;
import com.denimgroup.threadfix.data.entities.Finding;
import com.denimgroup.threadfix.service.AbstractNamedObjectService;
import com.denimgroup.threadfix.service.EndpointPermissionService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import javax.annotation.Nonnull;
import java.util.ArrayList;
import java.util.List;

/**
 * Created by mcollins on 3/31/15.
 */
@Service
public class EndpointPermissionServiceImpl
        extends AbstractNamedObjectService<EndpointPermission>
        implements EndpointPermissionService {

    @Autowired
    EndpointPermissionDao endpointPermissionDao;
    @Autowired
    ApplicationDao applicationDao;
    @Autowired
    FindingDao findingDao;

    @Override
    public void addToFinding(@Nonnull Finding finding, @Nonnull Integer applicationId, @Nonnull List<String> permissions) {

        finding.setEndpointPermissions(new ArrayList<EndpointPermission>());

        for (String stringPermission : permissions) {
            EndpointPermission permission = endpointPermissionDao.retrieveByNameAndApplication(stringPermission, applicationId);
            if (permission == null) {
                permission = new EndpointPermission();
                permission.setName(stringPermission);
                permission.setApplication(applicationDao.retrieveById(applicationId));
            }

            if (!permission.getFindingList().contains(finding)) {
                permission.getFindingList().add(finding);
            }

            endpointPermissionDao.saveOrUpdate(permission);
        }
    }

    @Override
    public GenericNamedObjectDao<EndpointPermission> getDao() {
        return endpointPermissionDao;
    }
}
