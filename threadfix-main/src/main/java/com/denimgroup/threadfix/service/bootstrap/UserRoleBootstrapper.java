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
package com.denimgroup.threadfix.service.bootstrap;

import com.denimgroup.threadfix.data.entities.Role;
import com.denimgroup.threadfix.data.entities.User;
import com.denimgroup.threadfix.logging.SanitizedLogger;
import com.denimgroup.threadfix.service.RoleService;
import com.denimgroup.threadfix.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import java.util.Date;
import java.util.List;

/**
 * Created by mcollins on 8/18/15.
 */
@Component
public class UserRoleBootstrapper {

    private static final SanitizedLogger LOG = new SanitizedLogger(UserRoleBootstrapper.class);

    @Autowired
    RoleService roleService;
    @Autowired
    UserService userService;

    @Transactional
    public void bootstrap() {
        sanityCheck();

        LOG.info("Populating initial user.");

        Role admin = new Role();
        admin.setCanGenerateReports(true);
        admin.setCanGenerateWafRules(true);
        admin.setCanManageApiKeys(true);
        admin.setCanManageEmailReports(true);
        admin.setCanManageApplications(true);
        admin.setCanManageGrcTools(true);
        admin.setCanManageDefectTrackers(true);
        admin.setCanManageRemoteProviders(true);
        admin.setCanManageRoles(true);
        admin.setCanManageTeams(true);
        admin.setCanManageUsers(true);
        admin.setCanManageWafs(true);
        admin.setCanManageVulnFilters(true);
        admin.setCanModifyVulnerabilities(true);
        admin.setCanSubmitDefects(true);
        admin.setCanUploadScans(true);
        admin.setCanManageScanAgents(true);
        admin.setCanManageSystemSettings(true);
        admin.setCanViewErrorLogs(true);
        admin.setCanManageTags(true);
        admin.setCanSubmitComments(true);
        admin.setCanManageScanResultFilters(true);
        admin.setCanManageCustomCweText(true);
        admin.setCanManagePolicies(true);
        admin.setDisplayName("Administrator");

        roleService.storeRole(admin);

        Role userRole = new Role();
        userRole.setDisplayName("User");
        roleService.storeRole(userRole);


        User user = new User();
        user.setName("user");
        user.setUnencryptedPassword("password"); // change it!
        user.setGlobalRole(admin);
        user.setHasGlobalGroupAccess(true);
        user.setCreatedDate(new Date());

        userService.storeUser(user);

    }

    private void sanityCheck() {
        List<User> users = userService.loadAllUsers();

        if (users.size() != 0) {
            throw new IllegalStateException("Attempted to add to users table when users already existed.");
        }

        List<Role> roles = roleService.loadAll();

        if (roles.size() != 0) {
            throw new IllegalStateException("Attempted to add to roles table when roles already existed.");
        }
    }
}
