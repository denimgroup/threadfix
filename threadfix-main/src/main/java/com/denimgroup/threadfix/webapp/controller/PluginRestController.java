////////////////////////////////////////////////////////////////////////
//
//     Copyright (c) 2009-2013 Denim Group, Ltd.
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
package com.denimgroup.threadfix.webapp.controller;

import java.util.Collection;
import java.util.List;

import javax.servlet.http.HttpServletRequest;

import com.denimgroup.threadfix.framework.engine.full.EndpointDatabaseFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.ResponseBody;

import com.denimgroup.threadfix.data.entities.Application;
import com.denimgroup.threadfix.data.entities.Vulnerability;
import com.denimgroup.threadfix.framework.engine.full.Endpoint;
import com.denimgroup.threadfix.framework.engine.full.EndpointGenerator;
import com.denimgroup.threadfix.service.APIKeyService;
import com.denimgroup.threadfix.service.ApplicationService;

@Controller
@RequestMapping("/rest/code")
public class PluginRestController extends RestController {
	
	private ApplicationService applicationService;
	
	@Autowired
	public PluginRestController(APIKeyService apiKeyService,
			ApplicationService applicationService) {
		super(apiKeyService);
		this.applicationService = applicationService;
	}

	@RequestMapping(value="/markers/{appId}", method=RequestMethod.GET)
	public @ResponseBody Object getMarkers(
			HttpServletRequest request,
			@PathVariable("appId") int appId) {
		log.info("Received REST request for marker information for application with id = " + appId);
		
		String result = checkKey(request, "markers");
		if (!result.equals(API_KEY_SUCCESS)) {
			return result;
		}
		
		Application application = applicationService.loadApplication(appId);
		
		if (application == null) {
			log.warn("Couldn't find the application with ID " + appId);
			return "failure";
		}
		
		return getMarkerCSV(application);
	}
	
	@RequestMapping(value="/applications", method=RequestMethod.GET)
	public @ResponseBody Object getApplicationList(HttpServletRequest request) {
		log.info("Received REST request for application CSV list");
		
		String result = checkKey(request, "markers");
		if (!result.equals(API_KEY_SUCCESS)) {
			return result;
		}
		
		List<Application> applications = applicationService.loadAllActive();
		
		if (applications == null) {
			log.warn("Couldn't find any active applications.");
			return "failure";
		}
		return getApplicationCSV(applications);
	}
	
	@RequestMapping(value="/applications/{appId}/endpoints", method=RequestMethod.GET)
	public @ResponseBody Object getEndpoints(@PathVariable int appId,
			HttpServletRequest request) {
		log.info("Received REST request for application CSV list");
		
		String result = checkKey(request, "markers");
		if (!result.equals(API_KEY_SUCCESS)) {
			return result;
		}
		
		Application application = applicationService.loadApplication(appId);
		
		if (application == null) {
			log.warn("Couldn't find the application.");
			return "failure";
		}
		
		EndpointGenerator generator =
				EndpointDatabaseFactory.getDatabase(application.getProjectConfig());
		
		if (generator != null) {
			return getEndpointCSV(generator);
		} else {
			return "failure";
		}
	}
	
	private String getEndpointCSV(EndpointGenerator generator) {
		StringBuilder builder = new StringBuilder();
		
		Collection<Endpoint> endpoints = generator.generateEndpoints();
		
        for (Endpoint endpoint : endpoints) {
            if (endpoint != null) {
                builder.append(endpoint.getCSVLine()).append("\n");
            }
		}
		
		return builder.toString();
	}
	
	private String getMarkerCSV(Application application) {
		StringBuilder builder = new StringBuilder();
		
		for (Vulnerability vulnerability : application.getVulnerabilities()) {
			if (vulnerability != null) {
				builder.append(vulnerability.getMarkerCSVLine()).append("\n");
			}
		}
		return builder.toString();
	}
	
	private String getApplicationCSV(List<Application> applications) {
		StringBuilder builder = new StringBuilder();

		for (Application application: applications) {
			if (application != null && application.getOrganization() != null && application.getId() != null) {
				builder.append(application.getOrganization().getName())
					.append("/")
					.append(application.getName())
					.append(",")
					.append(application.getId())
					.append("\n");
			}
		}
		
		return builder.toString();
	}
	
}
