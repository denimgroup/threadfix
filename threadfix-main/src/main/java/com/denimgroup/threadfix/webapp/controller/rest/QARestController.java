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
import com.denimgroup.threadfix.data.entities.Organization;
import com.denimgroup.threadfix.data.entities.User;
import com.denimgroup.threadfix.remote.response.RestResponse;
import com.denimgroup.threadfix.service.OrganizationService;
import com.denimgroup.threadfix.service.UserService;
import com.denimgroup.threadfix.views.AllViews;
import com.fasterxml.jackson.annotation.JsonView;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.http.HttpServletRequest;
import java.util.List;

@RestController
@RequestMapping("/rest")
public class QARestController extends TFRestController {

    @Autowired
    private OrganizationService organizationService;
    @Autowired
    private UserService userService;

    private static final String TEAM_DELETION_FAILED = "Team deletion failed.";
    private static final String TEAM_DELETION_SUCCESS= "Team deleted successfully";
    private static final String DELETE_TEAM = "deleteTeam";

    private static final String USER_DELETION_FAILED = "User deletion failed.";
    private static final String USER_DELETION_SUCCESS= "User deleted successfully";
    private static final String DELETE_USER = "deleteUser";

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
}
