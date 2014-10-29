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
package com.denimgroup.threadfix.webapp.controller.rest;

import com.denimgroup.threadfix.data.entities.Role;
import com.denimgroup.threadfix.remote.response.RestResponse;
import com.denimgroup.threadfix.service.RoleService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;

import static com.denimgroup.threadfix.remote.response.RestResponse.success;

/**
 * This is a QA only class so we can skip steps while testing
 *
 * Created by daniel on 8/6/14.
 */

@Controller
@RequestMapping("/rest/role")
public class RoleRestController {

    @Autowired
    RoleService roleService;

    @RequestMapping(value= "create", method = RequestMethod.POST)
    public @ResponseBody RestResponse<Role> createRole(@RequestParam String roleName,
                                                       @RequestParam Boolean allPermissions) {

        Role role = new Role();
        role.setDisplayName(roleName);

        if (allPermissions) {
            role.setCanGenerateReports(allPermissions);
            role.setCanGenerateWafRules(allPermissions);
            role.setCanManageApiKeys(allPermissions);
            role.setCanManageApplications(allPermissions);
            role.setCanManageDefectTrackers(allPermissions);
            role.setCanManageRemoteProviders(allPermissions);
            role.setCanManageScanAgents(allPermissions);
            role.setCanManageSystemSettings(allPermissions);
            role.setCanManageRoles(allPermissions);
            role.setCanManageTeams(allPermissions);
            role.setCanManageUsers(allPermissions);
            role.setCanManageUsers(allPermissions);
            role.setCanManageWafs(allPermissions);
            role.setCanManageVulnFilters(allPermissions);
            role.setCanModifyVulnerabilities(allPermissions);
            role.setCanSubmitDefects(allPermissions);
            role.setCanUploadScans(allPermissions);
            role.setCanViewErrorLogs(allPermissions);
        }

        roleService.storeRole(role);

        return success(role);
    }

    @RequestMapping(value= "create/specific", method = RequestMethod.POST)
    public @ResponseBody RestResponse<Role> permissionSpecificRole(@RequestParam String roleName,
                                                                   @RequestParam String permission) {

        Role role = new Role();
        role.setDisplayName(roleName);

        switch(permission) {
            case "canManageUsers":
                role.setCanManageUsers(true);
                break;
            case "canManageRoles":
                role.setCanManageRoles(true);
                break;
            case "canManageTeams":
                role.setCanManageTeams(true);
                break;
            case "canManageDefectTrackers":
                role.setCanManageDefectTrackers(true);
                break;
            case "canManageVulnFilters":
                role.setCanManageVulnFilters(true);
                break;
            case "canModifyVulnerabilities":
                role.setCanModifyVulnerabilities(true);
                break;
            case "canUploadScans":
                role.setCanUploadScans(true);
                break;
            case "canViewErrorLogs":
                role.setCanViewErrorLogs(true);
                break;
            case "canSubmitDefects":
                role.setCanSubmitDefects(true);
                break;
            case "canManageWafs":
                role.setCanManageWafs(true);
                break;
            case "canGenerateWafRules":
                role.setCanGenerateWafRules(true);
                break;
            case "canManageApiKeys":
                role.setCanManageApiKeys(true);
                break;
            case "canManageRemoteProviders":
                role.setCanManageRemoteProviders(true);
                break;
            case "canGenerateReports":
                role.setCanGenerateReports(true);
                break;
            case "canManageApplications":
                role.setCanManageApplications(true);
                break;
            case "canManageScanAgents":
                role.setCanManageScanAgents(true);
                break;
            case "canManageSystemSettings":
                role.setCanManageSystemSettings(true);
                break;
            case "canManageTags":
                role.setCanManageTags(true);
                break;
            default:
                throw new RuntimeException(permission + " is not a valid permission");
        }

        roleService.storeRole(role);

        return success(role);
    }

    @RequestMapping(value= "edit", method = RequestMethod.POST)
    public @ResponseBody RestResponse<Role> removePermission(@RequestParam String roleName,
                                                                   @RequestParam String permission) {

        Role role = roleService.loadRole(roleName);

        switch(permission) {
            case "canManageUsers":
                role.setCanManageUsers(false);
                break;
            case "canManageRoles":
                role.setCanManageRoles(false);
                break;
            case "canManageTeams":
                role.setCanManageTeams(false);
                break;
            case "canManageDefectTrackers":
                role.setCanManageDefectTrackers(false);
                break;
            case "canManageVulnFilters":
                role.setCanManageVulnFilters(false);
                break;
            case "canModifyVulnerabilities":
                role.setCanModifyVulnerabilities(false);
                break;
            case "canUploadScans":
                role.setCanUploadScans(false);
                break;
            case "canViewErrorLogs":
                role.setCanViewErrorLogs(false);
                break;
            case "canSubmitDefects":
                role.setCanSubmitDefects(false);
                break;
            case "canManageWafs":
                role.setCanManageWafs(false);
                break;
            case "canGenerateWafRules":
                role.setCanGenerateWafRules(false);
                break;
            case "canManageApiKeys":
                role.setCanManageApiKeys(false);
                break;
            case "canManageRemoteProviders":
                role.setCanManageRemoteProviders(false);
                break;
            case "canGenerateReports":
                role.setCanGenerateReports(false);
                break;
            case "canManageApplications":
                role.setCanManageApplications(false);
                break;
            case "canManageScanAgents":
                role.setCanManageScanAgents(false);
                break;
            case "canManageSystemSettings":
                role.setCanManageSystemSettings(false);
                break;
            case "canManageTags":
                role.setCanManageTags(false);
                break;
            default:
                throw new RuntimeException(permission + " is not a valid permission");
        }

        roleService.storeRole(role);

        return success(role);
    }

}
