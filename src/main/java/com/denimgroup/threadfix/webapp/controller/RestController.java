package com.denimgroup.threadfix.webapp.controller;

import java.util.List;

import javax.servlet.http.HttpServletRequest;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
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
@RequestMapping("/rest")
public class RestController {

	private final Log log = LogFactory.getLog(RestController.class);

	private OrganizationService organizationService = null;
	private APIKeyService apiKeyService = null;
	
	@Autowired
	public RestController(OrganizationService organizationService,
							APIKeyService apiKeyService) {
		this.organizationService = organizationService;
		this.apiKeyService = apiKeyService;
	}
	
	@RequestMapping(value="/teams", method=RequestMethod.GET, headers="Accept=application/json")
	public @ResponseBody Object teamList(HttpServletRequest request) {
		log.info("Received REST request for Team list.");
		
		if (!checkKey(request)) {
			return null;
		}
		List<Organization> orgList = organizationService.loadAll();
		
		if (orgList == null) {
			log.warn("REST request for Teams failed while trying to get a list of Teams.");
			return null;
		} else if (orgList.size() == 0) {
			log.info("Team lookup was successful, but there were 0 teams in the database.");
		} else {
			log.info("REST request for Team List completed successfully.");
		}
		
		return orgList;
	}
	
	@RequestMapping(value="/teams/{teamID}", method=RequestMethod.GET, headers="Accept=application/json")
	public @ResponseBody Object teamIDLookup(@PathVariable("teamID") int teamId, HttpServletRequest request) {
		log.info("Received REST request for Team with ID " + teamId + ".");
		
		if (!checkKey(request)) {
			return null;
		}
		
		Organization org = organizationService.loadOrganization(teamId);
		
		if (org == null) {
			log.warn("Team lookup failed for ID " + teamId + ".");
			return null;
		} else {
			log.info("REST request for Team with ID " + teamId + " completed successfully.");
			return org;
		}
	}
	
	@RequestMapping(value="/teams/new", method=RequestMethod.POST, headers="Accept=application/json")
	public @ResponseBody Object newTeam(HttpServletRequest request) {
		log.info("Received REST request for new Team.");
		
		if (!checkKey(request)) {
			return null;
		}

		if (request.getParameter("name") != null) {
			String name = request.getParameter("name");
			if (organizationService.loadOrganization(name) != null) {
				// TODO figure out what to do when the name already exists.
				log.warn("Attempted to create an already existing Team. Returning the old one.");
				return organizationService.loadOrganization(name);
			
			} else {
				Organization organization = new Organization();
				organization.setName(name);
				organizationService.storeOrganization(organization);
				log.info("Successfully created new Team.");
				return organization;
			}
		} else {
			log.warn("\"name\" parameter was not present, new Team creation failed.");
			return null;
		}
	}
	
    private boolean checkKey(HttpServletRequest request) {
    	String apiKey = request.getParameter("apiKey");
    	
    	if (apiKey == null) {
    		log.warn("Request to " + request.getPathInfo() + " did not contain an API Key.");
    		return false;
    	}
    	
    	boolean authentic = apiKeyService.checkKey(apiKey);
    	
    	if (authentic) {
    		log.info("API key " + apiKey + " authenticated successfully on " + request.getPathInfo() + ".");
    	} else {
    		log.warn("API key " + apiKey + " did not authenticate successfully on " + request.getPathInfo() + ".");
    	}
    	
    	return authentic;
    }
}
