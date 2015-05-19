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

import com.denimgroup.threadfix.data.entities.Application;
import com.denimgroup.threadfix.data.entities.ApplicationCriticality;
import com.denimgroup.threadfix.data.entities.Organization;
import com.denimgroup.threadfix.remote.response.RestResponse;
import com.denimgroup.threadfix.service.ApplicationCriticalityService;
import com.denimgroup.threadfix.service.ApplicationService;
import com.denimgroup.threadfix.service.LicenseService;
import com.denimgroup.threadfix.service.OrganizationService;
import com.denimgroup.threadfix.views.AllViews;
import com.fasterxml.jackson.annotation.JsonView;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.HttpServletRequest;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.List;

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
    public static final String LOOKUP_FAILED   = "Team Lookup failed.";

    private final static String DETAIL = "teamIDLookup",
            LOOKUP                     = "teamNameLookup",
            NEW                        = "newTeam",
            INDEX                      = "teamList",
            UPDATE                     = "putTeam";

    // TODO finalize which methods need to be restricted
    static {
        restrictedMethods.add(NEW);
    }

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
        log.info("Received REST request for Team with ID " + teamId + ".");

        String result = checkKey(request, DETAIL);
        if (!result.equals(API_KEY_SUCCESS)) {
            return RestResponse.failure(result);
        }

        Organization org = organizationService.loadById(teamId);

        if (org == null) {
            log.warn("Team lookup failed for ID " + teamId + ".");
            return RestResponse.failure(LOOKUP_FAILED);
        } else {
            log.info("REST request for Team with ID " + teamId
                    + " completed successfully.");
            return RestResponse.success(org);
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
        log.info("Received REST request for a new Application.");

        String result = checkKey(request, NEW);
        if (!result.equals(API_KEY_SUCCESS)) {
            return RestResponse.failure(result);
        }

        if (licenseService != null && !licenseService.canAddApps()) {
            return RestResponse.failure("The current license does not allow the creation of any more applications.");
        }

        // By not using @RequestParam notations, we can catch the error in the code
        // and provide better error messages.
        String name = request.getParameter("name");
        String url = request.getParameter("url");

        if (name == null) {
            log.warn("Call to New Application was missing the name parameter.");
			return RestResponse.failure(CREATION_FAILED);
		}
		
		if (url != null) {
			// test URL format
			try {
				new URL(url);
			} catch (MalformedURLException e) {
				log.warn("The supplied URL was not formatted correctly.");
				return RestResponse.failure(CREATION_FAILED);
			}
		}
		
		Organization organization = organizationService.loadById(teamId);
		
		if (organization == null) {
			log.warn("Invalid Team ID.");
			return RestResponse.failure(CREATION_FAILED);
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
			applicationService.storeApplication(application);
			log.info("Application creation was successful. Returning application.");
            return RestResponse.success(application);
		} else {
			//	TODO - We could really use some better debug here
			log.warn("Something was invalid.");
			return RestResponse.failure("Problems creating application.");
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
		
		log.info("Received REST request for Team with ID " + teamName + ".");

		String result = checkKey(request, LOOKUP);
		if (!result.equals(API_KEY_SUCCESS)) {
			return RestResponse.failure(result);
		}

		Organization org = organizationService.loadByName(teamName);

		if (org == null) {
			log.warn("Team lookup failed for ID " + teamName + ".");
			return RestResponse.failure("No team found with name '" + teamName + "'");
		} else {
			log.info("REST request for Team with ID " + teamName
					+ " completed successfully.");
            return RestResponse.success(org);
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
		log.info("Received REST request for new Team.");

		String result = checkKey(request, NEW);
		if (!result.equals(API_KEY_SUCCESS)) {
			return RestResponse.failure(result);
		}

		if (request.getParameter("name") != null) {
			
			Organization organization = new Organization();
			organization.setName(request.getParameter("name"));
			
			if (organizationService.isValidOrganization(organization)) {
				organizationService.saveOrUpdate(organization);
				log.info("Successfully created new Team.");
				return RestResponse.success(organization);
			} else {
				log.info(CREATION_FAILED);
				return RestResponse.failure(CREATION_FAILED);
			}
			
		} else {
			log.warn("\"name\" parameter was not present, new Team creation failed.");
			return RestResponse.failure("\"name\" parameter was not present, new Team creation failed.");
		}
	}



    /**
     * @see com.denimgroup.threadfix.remote.ThreadFixRestClient#getAllTeams()
     * @param request
     * @return
     */
	@RequestMapping(method = RequestMethod.GET, value = "/")
	@JsonView(AllViews.RestViewTeam2_1.class)
	public Object teamList(HttpServletRequest request) {
		log.info("Received REST request for Team list.");
		
		String result = checkKey(request, INDEX);
		if (!result.equals(API_KEY_SUCCESS)) {
			return RestResponse.failure(result);
		}

        List<Organization> organizations = organizationService.loadAllActive();

        if (organizations == null) {
            return RestResponse.failure("No organizations found.");
        } else {
            return RestResponse.success(organizations);
        }
	}
	
	@RequestMapping(method = RequestMethod.GET, value = "")
	public Object alsoTeamList(HttpServletRequest request) {
		return teamList(request);
	}

    @JsonView(AllViews.RestViewTeam2_1.class)
    @RequestMapping(method = RequestMethod.PUT, value = "/{teamId}/")
    public Object putTeam(HttpServletRequest request, @PathVariable("teamId") int teamId, @RequestBody String name){

        log.info("Received REST request to update Team");
        String result = checkKey(request, UPDATE);
        if(!result.equals(API_KEY_SUCCESS)) return RestResponse.failure(result);
        Organization organization = organizationService.loadById(teamId);
        if(organization == null){
            return RestResponse.failure(LOOKUP_FAILED);
        }else {
            organization.setName(name);
            organizationService.saveOrUpdate(organization);
            log.info("REST Request (PUT method) to update Team resource with id " + teamId + " is completed successfully");
            return RestResponse.success(organization);
        }
    }

}
