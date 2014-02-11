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

import com.denimgroup.threadfix.data.entities.Application;
import com.denimgroup.threadfix.data.entities.VulnerabilityMarker;
import com.denimgroup.threadfix.data.interfaces.Endpoint;
import com.denimgroup.threadfix.framework.engine.ProjectConfig;
import com.denimgroup.threadfix.framework.engine.full.EndpointDatabaseFactory;
import com.denimgroup.threadfix.framework.engine.full.EndpointGenerator;
import com.denimgroup.threadfix.remote.response.RestResponse;
import com.denimgroup.threadfix.service.ApplicationService;
import com.denimgroup.threadfix.service.repository.GitService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.ResponseBody;

import javax.servlet.http.HttpServletRequest;
import java.util.ArrayList;
import java.util.List;

@Controller
@RequestMapping("/rest/code")
public class PluginRestController extends RestController {

    @Autowired
	private ApplicationService applicationService;

    /**
     *
     * @see com.denimgroup.threadfix.remote.PluginClient#getVulnerabilityMarkers(String)
     * @param request
     * @param appId
     * @return
     */
	@RequestMapping(value="/markers/{appId}", method=RequestMethod.GET)
	public @ResponseBody RestResponse<VulnerabilityMarker[]> getMarkers(
			HttpServletRequest request,
			@PathVariable("appId") int appId) {
		log.info("Received REST request for marker information for application with id = " + appId);
		
		String result = checkKey(request, "markers");
		if (!result.equals(API_KEY_SUCCESS)) {
			return RestResponse.failure(result);
		}
		
		Application application = applicationService.loadApplication(appId);
		
		if (application == null) {
            String message = "Couldn't find the application with ID " + appId;
			log.warn(message);
			return RestResponse.failure(message);
		}
		
		return RestResponse.success(application.getMarkers());
	}

    /**
     *
     * @see com.denimgroup.threadfix.remote.PluginClient#getThreadFixApplications()
     * @param request
     * @return
     */
	@RequestMapping(value="/applications", method=RequestMethod.GET)
	public @ResponseBody RestResponse<Application.Info[]> getApplicationList(HttpServletRequest request) {
		log.info("Received REST request for application CSV list");
		
		String result = checkKey(request, "markers");
		if (!result.equals(API_KEY_SUCCESS)) {
            return RestResponse.failure(result);
		}
		
		List<Application> applications = applicationService.loadAllActive();
		
		if (applications == null) {
            String response = "Couldn't find any active applications.";
			log.warn(response);
			RestResponse.failure(response);
		}
		return RestResponse.success(getApplicationInfo(applications));
	}

    /**
     * @see com.denimgroup.threadfix.remote.PluginClient#getEndpoints(String)
     * @param appId
     * @param request
     * @return
     */
	@RequestMapping(value="/applications/{appId}/endpoints", method=RequestMethod.GET)
	public @ResponseBody RestResponse<Endpoint.Info[]> getEndpoints(@PathVariable int appId,
			HttpServletRequest request) {
		log.info("Received REST request for application CSV list");
		
		String result = checkKey(request, "markers");
		if (!result.equals(API_KEY_SUCCESS)) {
			return RestResponse.failure(result);
		}
		
		Application application = applicationService.loadApplication(appId);
		
		if (application == null) {
            String message = "Couldn't find the application.";
			log.warn(message);
			return RestResponse.failure(message);
		}
		
		EndpointGenerator generator =
				EndpointDatabaseFactory.getDatabase(getProjectConfig(application));
		
		if (generator != null) {
            List<Endpoint> endpoints = generator.generateEndpoints();


			return RestResponse.success(getEndpointInfo(endpoints));
		} else {
			return RestResponse.failure("Unable to create an EndpointGenerator.");
		}
	}

    public ProjectConfig getProjectConfig(Application application) {
        return new ProjectConfig(application.getFrameworkTypeEnum(),
                application.getSourceCodeAccessLevelEnum(),
                GitService.getWorkTree(application),
                application.getProjectRoot()
        );
    }
	
	private Application.Info[] getApplicationInfo(List<Application> applications) {
		List<Application.Info> infoList = new ArrayList<>();

		for (Application application: applications) {
			if (application != null && application.getOrganization() != null && application.getId() != null) {
                infoList.add(application.getInfo());
			}
		}
		
		return infoList.toArray(new Application.Info[infoList.size()]);
	}

    private Endpoint.Info[] getEndpointInfo(List<Endpoint> endpoints) {
        Endpoint.Info[] endpointsInfos = new Endpoint.Info[endpoints.size()];

        for (int i = 0; i < endpoints.size(); i++) {
            endpointsInfos[i] = Endpoint.Info.fromEndpoint(endpoints.get(i));
        }

        return endpointsInfos;
    }
}
