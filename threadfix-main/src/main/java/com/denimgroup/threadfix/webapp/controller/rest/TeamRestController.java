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

package com.denimgroup.threadfix.webapp.controller.rest;

import com.denimgroup.threadfix.data.entities.Application;
import com.denimgroup.threadfix.data.entities.ApplicationCriticality;
import com.denimgroup.threadfix.data.entities.Organization;
import com.denimgroup.threadfix.data.enums.EventAction;
import com.denimgroup.threadfix.service.ApplicationCriticalityService;
import com.denimgroup.threadfix.service.ApplicationService;
import com.denimgroup.threadfix.service.LicenseService;
import com.denimgroup.threadfix.service.OrganizationService;
import com.denimgroup.threadfix.util.Result;
import com.denimgroup.threadfix.views.AllViews;
import com.fasterxml.jackson.annotation.JsonView;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.util.MultiValueMap;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.HttpServletRequest;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.List;
import java.util.Map;

import static com.denimgroup.threadfix.remote.response.RestResponse.*;
import static com.denimgroup.threadfix.util.ValidationUtils.HTML_ERROR;
import static com.denimgroup.threadfix.util.ValidationUtils.containsHTML;
import static com.denimgroup.threadfix.webapp.controller.rest.RestMethod.*;

@RestController
@RequestMapping("/rest/teams")
public class TeamRestController extends TFRestController {
    @Autowired
    private OrganizationService           organizationService;
    @Autowired
    private ApplicationService            applicationService;
    @Autowired
    private ApplicationCriticalityService applicationCriticalityService;
    @Autowired(required = false)
    private LicenseService                licenseService;

    public static final String CREATION_FAILED = "New Team creation failed.";
    public static final String APP_CREATION_FAILED = "New Application creation failed.";
    public static final String LOOKUP_FAILED   = "Team Lookup failed.";
    public static final String INVALID_PARAMS  = "Invalid parameters entered";
    public static final String PUT_SUCCESS     = "Fields updated successfully";

    /**
     * @see com.denimgroup.threadfix.remote.ThreadFixRestClient#searchForTeamById(String)
     * @param teamId
     * @param request
     * @return
     */
    @RequestMapping(headers = "Accept=application/json", value = "/{teamID}", method = RequestMethod.GET)
    @JsonView(AllViews.RestViewTeam2_1.class)
	public Object teamIDLookup(@PathVariable("teamID") int teamId,
                        HttpServletRequest request) {
        LOG.info("Received REST request for Team with ID " + teamId + ".");

        Result<String> keyCheck = checkKey(request, TEAM_LOOKUP, teamId, -1);
        if (!keyCheck.success()) {
            return resultError(keyCheck);
        }

        Organization org = organizationService.loadById(teamId);

        if (org == null || !org.isActive()) {
            LOG.warn("Team lookup failed for ID " + teamId + ".");
            return failure(LOOKUP_FAILED);
        } else {
            LOG.info("REST request for Team with ID " + teamId
                    + " completed successfully.");
            return success(org);
        }
    }

    /**
     * @see com.denimgroup.threadfix.remote.ThreadFixRestClient#createApplication(String, String, String)
     * Create a new application with the supplied name and URL.
     * The rest of the configuration is done through other methods.
     */
	@JsonView(AllViews.RestViewApplication2_1.class)
    @RequestMapping(headers = "Accept=application/json", value = "/{teamId}/applications/new", method = RequestMethod.POST)
    public Object newApplication(HttpServletRequest request,
                          @PathVariable("teamId") int teamId) {
        LOG.info("Received REST request for a new Application.");

        Result<String> keyCheck = checkKey(request, TEAM_NEW_APPLICATION, teamId, -1);
        if (!keyCheck.success()) {
            return resultError(keyCheck);
        }

        if (licenseService != null && !licenseService.canAddApps()) {
            return failure("The current license does not allow the creation of any more applications.");
        }

        Organization organization = organizationService.loadById(teamId);
        if (organization == null) {
            LOG.warn("Invalid Team ID.");
            return failure("Invalid Team ID.");
        } else if (!organization.isActive()) {
            LOG.warn("Team has been deleted.");
            return failure("Team has been deleted.");
        }

        // By not using @RequestParam notations, we can catch the error in the code
        // and provide better error messages.
        String name = request.getParameter("name");
        String url = request.getParameter("url");

        if (name == null || name.trim().isEmpty()) {
            LOG.warn("Call to New Application was missing the name parameter.");
			return failure(APP_CREATION_FAILED);
		}

        if (containsHTML(name)) {
            LOG.error(HTML_ERROR);
            return failure(HTML_ERROR);
        }
		
		if (url != null) {
			// test URL format
			try {
                // TODO substitute commons url validator to avoid performance hit of creating exception
				new URL(url);
			} catch (MalformedURLException e) {
				LOG.warn("The supplied URL was not formatted correctly.");
				return failure(APP_CREATION_FAILED);
			}
		}
		
		Application application = new Application();
        application.setOrganization(organization);
        application.setName(name.trim());
        if (url != null) {
            application.setUrl(url.trim());
        }
        // TODO include this as a parameter
        application.setApplicationCriticality(
                applicationCriticalityService.loadApplicationCriticality(
                        ApplicationCriticality.LOW));

		if (applicationService.checkApplication(application)) {
			applicationService.storeApplication(application, EventAction.APPLICATION_CREATE);
			LOG.info("Application creation was successful. Returning application.");
            return success(application);
		} else {
			//	TODO - We could really use some better debug here
			LOG.warn("Something was invalid.");
			return failure("Problems creating application.");
		}
	}

    /**
     * @see com.denimgroup.threadfix.remote.ThreadFixRestClient#searchForTeamByName(String)
     * @param request
     * @return
     */
	@JsonView(AllViews.RestViewTeam2_1.class)
	@RequestMapping(headers = "Accept=application/json", value="/lookup", method = RequestMethod.GET)
	public Object teamNameLookup(HttpServletRequest request) {
		
		String teamName = request.getParameter("name");
		
		LOG.info("Received REST request for Team with name " + teamName + ".");

        // we'll check again for access to the actual team later
        Result<String> keyCheck = checkKeyGlobal(request, TEAM_LOOKUP);
        if (!keyCheck.success()) {
            return resultError(keyCheck);
        }

		Organization org = organizationService.loadByName(teamName);

		if (org == null) {
			LOG.warn("Team lookup failed for name " + teamName + ".");
			return failure("No team found with name '" + teamName + "'");
		} else {

            keyCheck = checkKey(request, TEAM_LOOKUP, org.getId(), -1);
            if (!keyCheck.success()) {
                return resultError(keyCheck);
            }

			LOG.info("REST request for Team with name " + teamName
                    + " completed successfully.");
            return success(org);
		}
	}

    /**
     * @see com.denimgroup.threadfix.remote.ThreadFixRestClient#createTeam(String)
     * @param request
     * @return
     */
	@RequestMapping(headers = "Accept=application/json", value = "/new", method = RequestMethod.POST,
            produces = "application/json; charset=utf-8")
	@JsonView(AllViews.RestViewTeam2_1.class)
	public Object newTeam(HttpServletRequest request) {
		LOG.info("Received REST request for new Team.");

        Result<String> keyCheck = checkKey(request, TEAM_NEW, -1, -1);
        if (!keyCheck.success()) {
            return resultError(keyCheck);
        }

		if (request.getParameter("name") != null) {
			
			Organization organization = new Organization();
			organization.setName(request.getParameter("name"));

            if (containsHTML(organization.getName())) {
                LOG.error(HTML_ERROR);
                return failure(HTML_ERROR);
            }
			
			if (organizationService.isValidOrganization(organization)) {
				organizationService.saveOrUpdate(organization);
				LOG.info("Successfully created new Team.");
				return success(organization);
			} else {
				LOG.info(CREATION_FAILED);
				return failure(CREATION_FAILED);
			}
			
		} else {
			LOG.warn("\"name\" parameter was not present, new Team creation failed.");
			return failure("\"name\" parameter was not present, new Team creation failed.");
		}
	}

    /**
     * @see com.denimgroup.threadfix.remote.ThreadFixRestClient#getAllTeams()
     * @param request
     * @return
     */
	@RequestMapping(method = RequestMethod.GET, value = "/")
	@JsonView(AllViews.RestViewTeams2_1.class)
	public Object teamList(HttpServletRequest request) {
		LOG.info("Received REST request for Team list.");
		
        Result<String> keyCheck = checkKey(request, TEAM_LIST, -1, -1);
        if (!keyCheck.success()) {
            return resultError(keyCheck);
        }

        List<Organization> organizations = organizationService.loadAllActive();

        if (organizations == null) {
            return failure("No organizations found.");
        } else {
            return success(organizations);
        }
	}
	
	@RequestMapping(method = RequestMethod.GET, value = "")
    @JsonView(AllViews.RestViewTeams2_1.class)
	public Object alsoTeamList(HttpServletRequest request) {
		return teamList(request);
	}

    @RequestMapping(method = RequestMethod.PUT, value = "/{teamId}/update", consumes = "application/x-www-form-urlencoded")
    public Object putTeam(HttpServletRequest request, @PathVariable("teamId") int teamId, @RequestBody MultiValueMap<String, String> params){

        LOG.info("Received REST request to update Team");
        Result<String> keyCheck = checkKey(request, TEAM_UPDATE, teamId, -1);
        if (!keyCheck.success()) {
            return resultError(keyCheck);
        }

        Organization organization = organizationService.loadById(teamId);

        if (organization == null) {
            return failure(LOOKUP_FAILED);
        } else {
            Map<String, String> map = params.toSingleValueMap();
            if (map.get("name") != null && !(map.get("name").isEmpty())) {
                organization.setName(map.get("name"));
                organizationService.saveOrUpdate(organization);
                LOG.info("REST Request (PUT method) to update Team resource with name " + teamId + " is completed successfully");
                return success(PUT_SUCCESS);
            } else {
                LOG.warn("Name parameter in the REST request is invalid. Returning failure response");
                return failure(INVALID_PARAMS);
            }
        }
    }

}
