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

package com.denimgroup.threadfix.webapp.controller.rest;

import com.denimgroup.threadfix.CollectionUtils;
import com.denimgroup.threadfix.data.entities.*;
import com.denimgroup.threadfix.remote.response.RestResponse;
import com.denimgroup.threadfix.service.*;
import com.denimgroup.threadfix.views.AllViews;
import com.fasterxml.jackson.annotation.JsonView;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.HttpServletRequest;
import java.util.List;

import static com.denimgroup.threadfix.remote.response.RestResponse.success;

@RestController
@RequestMapping("/rest")
public class QARestController extends TFRestController {

    @Autowired
    private OrganizationService organizationService;
    @Autowired
    private UserService userService;
    @Autowired
    private RoleService roleService;
    @Autowired
    private ApplicationService applicationService;
    @Autowired
    private AccessControlMapService accessControlMapService;
    @Autowired
    private GroupService groupService;

    private static final String TEAM_DELETION_FAILED = "Team deletion failed.";
    private static final String TEAM_DELETION_SUCCESS= "Team deleted successfully";
    private static final String DELETE_TEAM = "deleteTeam";

    private static final String USER_DELETION_FAILED = "User deletion failed.";
    private static final String USER_DELETION_SUCCESS= "User deleted successfully";
    private static final String DELETE_USER = "deleteUser";


    /********************************
     * TEAM METHODS
     ********************************/

    @RequestMapping(headers = "Accept=application/json", value = "/teams/delete/{teamId}", method = RequestMethod.POST)
    @JsonView(AllViews.RestViewTeam2_1.class)
    public Object deleteTeam(HttpServletRequest request, @PathVariable("teamId") int teamId) {
        log.info("Received REST request to delete Team with id " + teamId + ".");

        String result = checkKey(request, DELETE_TEAM);
        if (!result.equals(API_KEY_SUCCESS)) {
            return RestResponse.failure(result);
        }

        Organization organization = organizationService.loadById(teamId);

        if (organization == null || !organization.isActive()) {
            log.warn("Invalid Team ID.");
            return RestResponse.failure(TEAM_DELETION_FAILED);

        } else {
            String teamName = organization.getName();
            organizationService.markInactive(organization);
            log.info("REST Request to delete Team " + teamName + " is completed successfully");
            return RestResponse.success(TEAM_DELETION_SUCCESS);
        }
    }

    /********************************
     * USER METHODS
     ********************************/

    @RequestMapping(value = "/user/create", method = RequestMethod.POST)
    public @ResponseBody
    RestResponse<User> createUser(@RequestParam String username,
                                  @RequestParam(required = false) String globalRoleName) {

        User user = new User();
        user.setName(username);

        user.setHasGlobalGroupAccess(globalRoleName != null);
        if (globalRoleName != null) {
            user.setGlobalRole(roleService.loadRole(globalRoleName));
        }

        user.setSalt("c892c2c6-2bd9-4b6a-a826-d9a71f5db441");
        user.setPassword("3ac7de35360886d9aa7c821e4908f7c260c63eea9c229bff38ac40b28279b7a5");

        userService.storeUser(user);

        return success(user);
    }

    @RequestMapping(value= "/user/permission", method =  RequestMethod.POST)
    public @ResponseBody RestResponse<User> addUserTeamAppPermission(@RequestParam String username,
                                                                     @RequestParam String rolename,
                                                                     @RequestParam String teamname,
                                                                     @RequestParam String appname) {

        User user = userService.loadUser(username);

        AccessControlTeamMap newAccessControlTeamMap = new AccessControlTeamMap();

        newAccessControlTeamMap.setUser(user);
        newAccessControlTeamMap.setOrganization(organizationService.loadByName(teamname));
        newAccessControlTeamMap.setRole(roleService.loadRole(rolename));
        newAccessControlTeamMap.setAllApps(true);

        accessControlMapService.store(newAccessControlTeamMap);

        List<AccessControlTeamMap> userControlTeamMap = accessControlMapService.loadAllMapsForUser(user.getId());
        int controlTeamMapID = userControlTeamMap.get(0).getId();

        List<AccessControlTeamMap> accessControlTeamMapList = user.getAccessControlTeamMaps();
        accessControlTeamMapList.add(accessControlMapService.loadAccessControlTeamMap(controlTeamMapID));

        user.setAccessControlTeamMaps(accessControlTeamMapList);

        userService.storeUser(user);

        return success(user);
    }

    @RequestMapping(value="/user/trap", method = RequestMethod.POST)
    public @ResponseBody void trap() {
        String a = null;
        a.length();
    }

    @RequestMapping(headers = "Accept=application/json", value = "/user/delete/{userId}", method = RequestMethod.POST)
    public Object deleteUser(HttpServletRequest request, @PathVariable("userId") int userId) {
        log.info("Received REST request to delete User with id " + userId + ".");

        String result = checkKey(request, DELETE_USER);
        if (!result.equals(API_KEY_SUCCESS)) {
            return RestResponse.failure(result);
        }

        User user = userService.loadUser(userId);

        if (user == null || !user.isActive()) {
            log.warn("Invalid User ID.");
            return RestResponse.failure(USER_DELETION_FAILED);

        } else if(!userService.canDelete(user)) {
            log.warn("Cannot delete this User without removing access to critical funtions.");
            return RestResponse.failure(USER_DELETION_FAILED);
        } else {
            String userName = user.getName();
            userService.delete(user);
            log.info("REST Request to delete User " + userName + " is completed successfully");
            return RestResponse.success(USER_DELETION_SUCCESS);
        }
    }

    @RequestMapping(headers = "Accept=application/json", value = "/user/list", method = RequestMethod.POST)
    public Object listUsers(HttpServletRequest request) {
        log.info("Recieved REST request to list Users");

        List<User> users = userService.loadAllUsers();

        return RestResponse.success(users);
    }

    /********************************
     * ROLE METHODS
     ********************************/

    @RequestMapping(value= "/role/create", method = RequestMethod.POST)
    public @ResponseBody RestResponse<Role> createRole(@RequestParam String roleName,
                                                       @RequestParam Boolean allPermissions) {

        Role role = new Role();
        role.setDisplayName(roleName);

        if (allPermissions) {
            role.setCanGenerateReports(allPermissions);
            role.setCanGenerateWafRules(allPermissions);
            role.setCanManageApiKeys(allPermissions);
            role.setCanManageApplications(allPermissions);
            role.setCanManageGrcTools(allPermissions);
            role.setCanManageDefectTrackers(allPermissions);
            role.setCanManageRemoteProviders(allPermissions);
            role.setCanManageScanAgents(allPermissions);
            role.setCanManageSystemSettings(allPermissions);
            role.setCanManageRoles(allPermissions);
            role.setCanManageTags(allPermissions);
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

    @RequestMapping(value= "/role/create/specific", method = RequestMethod.POST)
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
            case "canManageGRCTools":
                role.setCanManageGrcTools(true);
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

    @RequestMapping(value= "/role/edit", method = RequestMethod.POST)
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

    /********************************
     * GROUP METHODS
     ********************************/

    @RequestMapping(headers = "Accept=application/json", value = "/groups/create", method = RequestMethod.POST)
    public @ResponseBody RestResponse<Group> createGroup(@RequestParam String groupName) {
        Group group = new Group();
        group.setName(groupName);

        groupService.saveOrUpdate(group);

        return success(group);
    }

}
