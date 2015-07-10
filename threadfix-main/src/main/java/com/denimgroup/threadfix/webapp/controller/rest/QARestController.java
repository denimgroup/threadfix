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

import com.denimgroup.threadfix.data.entities.Organization;
import com.denimgroup.threadfix.remote.response.RestResponse;
import com.denimgroup.threadfix.service.OrganizationService;
import com.denimgroup.threadfix.views.AllViews;
import com.fasterxml.jackson.annotation.JsonView;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.http.HttpServletRequest;

@RestController
@RequestMapping("/rest")
public class QARestController extends TFRestController {
    @Autowired
    private OrganizationService organizationService;

    public static final String DELETION_FAILED = "Team deletion failed.";
    public static final String DELETION_SUCCESS= "Team deleted successfully";
    private final static String DELETE = "deleteTeam";

    @RequestMapping(headers = "Accept=application/json", value = "/teams/delete/{teamId}", method = RequestMethod.POST)
    @JsonView(AllViews.RestViewTeam2_1.class)
    public Object deleteTeam(HttpServletRequest request, @PathVariable("teamId") int teamId) {
        log.info("Received REST request to delete Team with id " + teamId + ".");

        String result = checkKey(request, DELETE);
        if (!result.equals(API_KEY_SUCCESS)) {
            return RestResponse.failure(result);
        }

        Organization organization = organizationService.loadById(teamId);

        if (organization == null || !organization.isActive()) {
            log.warn("Invalid Team ID.");
            return RestResponse.failure(DELETION_FAILED);

        } else {
            String teamName = organization.getName();
            organizationService.markInactive(organization);
            log.info("REST Request to delete Team " + teamName + " is completed successfully");
            return RestResponse.success(DELETION_SUCCESS);
        }
    }
}
