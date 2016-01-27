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
import com.denimgroup.threadfix.data.entities.VulnerabilityMarker;
import com.denimgroup.threadfix.data.interfaces.Endpoint;
import com.denimgroup.threadfix.framework.engine.ProjectConfig;
import com.denimgroup.threadfix.framework.engine.full.EndpointDatabaseFactory;
import com.denimgroup.threadfix.framework.engine.full.EndpointGenerator;
import com.denimgroup.threadfix.importer.util.IntegerUtils;
import com.denimgroup.threadfix.remote.response.RestResponse;
import com.denimgroup.threadfix.service.ApplicationService;
import com.denimgroup.threadfix.service.RepositoryService;
import com.denimgroup.threadfix.service.repository.RepositoryServiceFactory;
import com.denimgroup.threadfix.util.Result;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.HttpServletRequest;
import java.util.Collections;
import java.util.Comparator;
import java.util.List;

import static com.denimgroup.threadfix.CollectionUtils.list;
import static com.denimgroup.threadfix.remote.response.RestResponse.resultError;

@RestController
@RequestMapping("/rest/code")
public class PluginRestController extends TFRestController {

    @Autowired
    private ApplicationService applicationService;

    @Autowired
    private RepositoryServiceFactory repositoryServiceFactory;

    /**
     *
     * @see com.denimgroup.threadfix.remote.PluginClient#getVulnerabilityMarkers(String)
     */
    @RequestMapping(value = "/markers/{appId}", method = RequestMethod.GET)
    public RestResponse<VulnerabilityMarker[]> getMarkers(
            HttpServletRequest request,
            @PathVariable("appId") int appId) {
        LOG.info("Received REST request for marker information for application with id = " + appId);

        Result<String> keyCheck = checkKey(request, RestMethod.PLUGIN_MARKERS, -1, -1);
        if (!keyCheck.success()) {
            return resultError(keyCheck);
        }

        Application application = applicationService.loadApplication(appId);

        if (application == null) {
            String message = "Couldn't find the application with ID " + appId;
            LOG.warn(message);
            return RestResponse.failure(message);
        }

        List<VulnerabilityMarker> markers = application.getMarkers();

        Collections.sort(markers, new VulnMarkerComparator());

        return RestResponse.success(markers.toArray(new VulnerabilityMarker[markers.size()]));
    }

    /**
     *
     * @see com.denimgroup.threadfix.remote.PluginClient#getThreadFixApplications()
     */
    @RequestMapping(value = "/applications", method = RequestMethod.GET)
    @ResponseBody
    public RestResponse<Application.Info[]> getApplicationList(HttpServletRequest request) {
        LOG.info("Received REST request for application CSV list");

        Result<String> keyCheck = checkKey(request, RestMethod.PLUGIN_APPLICATIONS, -1, -1);
        if (!keyCheck.success()) {
            return resultError(keyCheck);
        }

        List<Application> applications = applicationService.loadAllActive();

        if (applications == null) {
            String response = "Couldn't find any active applications.";
            LOG.warn(response);
            RestResponse.failure(response);
        }
        return RestResponse.success(getApplicationInfo(applications));
    }

    /**
     * @see com.denimgroup.threadfix.remote.PluginClient#getEndpoints(String)
     */
    @RequestMapping(value = "/applications/{appId}/endpoints", method = RequestMethod.GET)
    public
    @ResponseBody
    RestResponse<Endpoint.Info[]> getEndpoints(@PathVariable int appId,
                                               HttpServletRequest request) {
        LOG.info("Received REST request for application CSV list");

        Result<String> keyCheck = checkKey(request, RestMethod.PLUGIN_ENDPOINTS, -1, -1);
        if (!keyCheck.success()) {
            return resultError(keyCheck);
        }

        Application application = applicationService.loadApplication(appId);
		
		if (application == null) {
            String message = "Couldn't find the application.";
			LOG.warn(message);
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

        RepositoryService repositoryService = repositoryServiceFactory.getRepositoryService(application);

        return new ProjectConfig(application.getFrameworkTypeEnum(),
                application.getSourceCodeAccessLevelEnum(),
                repositoryService.getWorkTree(application),
                application.getProjectRoot()
        );
    }
	
	private Application.Info[] getApplicationInfo(List<Application> applications) {
		List<Application.Info> infoList = list();

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

    // TODO rewrite / move
    public static class VulnMarkerComparator implements Comparator<VulnerabilityMarker> {

        @Override
        public int compare(VulnerabilityMarker marker1, VulnerabilityMarker marker2) {
            int score = nullSafeCompare(marker1.getFilePath(), marker2.getFilePath());

            if (score != 0) {
                return score;
            }

            score = nullSafeStringToIntCompare(marker1.getLineNumber(), marker2.getLineNumber());

            if (score != 0) {
                return score;
            }

            score = nullSafeStringToIntCompare(marker1.getGenericVulnId(), marker2.getGenericVulnId());

            return score;
        }

        int nullSafeCompare(String a, String b) {
            return a == null && b == null ? 0 :
                    a == null ? -1 :
                    b == null ?  1 :
                    a.compareTo(b);
        }

        int nullSafeStringToIntCompare(String a, String b) {

            Integer aAsInt = a == null ? null : IntegerUtils.getIntegerOrNull(a);
            Integer bAsInt = b == null ? null : IntegerUtils.getIntegerOrNull(b);

            return aAsInt == null && bAsInt == null ? 0 :
                    aAsInt == null ? -1 :
                    bAsInt == null ?  1 :
                    aAsInt.compareTo(bAsInt);

        }
    }
}
