package com.denimgroup.threadfix.webapp.controller;

import java.util.List;

import javax.servlet.http.HttpServletRequest;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.ResponseBody;

import com.denimgroup.threadfix.data.entities.Organization;
import com.denimgroup.threadfix.service.APIKeyService;
import com.denimgroup.threadfix.service.OrganizationService;

@Controller
@RequestMapping("/rest/teams")
public class OrganizationRestController extends RestController {

	private OrganizationService organizationService;
	
	public static final String CREATION_FAILED = "New Team creation failed.";
	public static final String LOOKUP_FAILED = "Team Lookup failed.";
	
	@Autowired
	public OrganizationRestController(OrganizationService organizationService,
			APIKeyService apiKeyService) {
		this.organizationService = organizationService;
		this.apiKeyService = apiKeyService;
	}

	@RequestMapping(headers = "Accept=application/json", value="/{teamID}", method = RequestMethod.GET)
	public @ResponseBody Object teamIDLookup(@PathVariable("teamID") int teamId,
			HttpServletRequest request) {
		log.info("Received REST request for Team with ID " + teamId + ".");

		if (!checkKey(request)) {
			return API_KEY_ERROR;
		}

		Organization org = organizationService.loadOrganization(teamId);

		if (org == null) {
			log.warn("Team lookup failed for ID " + teamId + ".");
			return LOOKUP_FAILED;
		} else {
			log.info("REST request for Team with ID " + teamId
					+ " completed successfully.");
			return org;
		}
	}

	@RequestMapping(headers = "Accept=application/json", value = "/new", method = RequestMethod.POST)
	public @ResponseBody Object newTeam(HttpServletRequest request) {
		log.info("Received REST request for new Team.");

		if (!checkKey(request)) {
			return API_KEY_ERROR;
		}

		if (request.getParameter("name") != null) {
			
			Organization organization = new Organization();
			organization.setName(request.getParameter("name"));
			
			if (organizationService.isValidOrganization(organization)) {
				organizationService.storeOrganization(organization);
				log.info("Successfully created new Team.");
				return organization;
			} else {
				log.info(CREATION_FAILED);
				return CREATION_FAILED;
			}
			
		} else {
			log.warn("\"name\" parameter was not present, new Team creation failed.");
			return "\"name\" parameter was not present, new Team creation failed.";
		}
	}
	
	@RequestMapping(method = RequestMethod.GET, value = "/")
	public @ResponseBody Object teamList(HttpServletRequest request) {
		log.info("Received REST request for Team list.");
		
		if (!checkKey(request)) {
			return API_KEY_ERROR;
		}
		
		List<Organization> organizations = organizationService.loadAll();

		return organizations;
	}
	
	@RequestMapping(method = RequestMethod.GET, value = "")
	public @ResponseBody Object alsoTeamList(HttpServletRequest request) {
		return teamList(request);
	}

}
