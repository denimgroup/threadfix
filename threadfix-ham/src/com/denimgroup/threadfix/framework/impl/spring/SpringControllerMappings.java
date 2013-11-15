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
package com.denimgroup.threadfix.framework.impl.spring;

import java.io.File;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;

import org.apache.commons.io.FileUtils;
import org.apache.commons.io.filefilter.TrueFileFilter;

import com.denimgroup.threadfix.framework.engine.full.Endpoint;
import com.denimgroup.threadfix.framework.engine.full.EndpointGenerator;
import com.denimgroup.threadfix.framework.util.FilePathUtils;

public class SpringControllerMappings implements EndpointGenerator {
	
	private final Collection<File> controllerFiles;
	
	private final Map<String, Set<SpringControllerEndpoint>> urlToControllerMethodsMap;
	private final Map<String, Set<SpringControllerEndpoint>> controllerToUrlsMap;
	
	private final File rootDirectory;
	
	@SuppressWarnings("unchecked")
	public SpringControllerMappings(File rootDirectory) {
		this.rootDirectory = rootDirectory;
		if (rootDirectory != null && rootDirectory.exists()) {
			controllerFiles = FileUtils.listFiles(rootDirectory,
					SpringControllerFileFilter.INSTANCE, TrueFileFilter.INSTANCE);
		
			urlToControllerMethodsMap = new HashMap<>();
			controllerToUrlsMap = new HashMap<>();
			
			if (controllerFiles != null) {
				generateMaps();
			}
		} else {
			controllerFiles = null;
			urlToControllerMethodsMap = null;
			controllerToUrlsMap = null;
		}
	}
	
	public Set<SpringControllerEndpoint> getEndpointsFromController(String controllerPath) {
		if (controllerToUrlsMap != null && controllerToUrlsMap.containsKey(controllerPath)) {
			return controllerToUrlsMap.get(controllerPath);
		} else {
			return new HashSet<>();
		}
	}
	
	public Set<SpringControllerEndpoint> getEndpointsFromUrl(String controllerPath) {
		if (urlToControllerMethodsMap != null && urlToControllerMethodsMap.containsKey(controllerPath)) {
			return urlToControllerMethodsMap.get(controllerPath);
		} else {
			return new HashSet<>();
		}
	}
	
	private void generateMaps() {
		if (controllerFiles == null ||
				urlToControllerMethodsMap == null ||
				controllerToUrlsMap == null) {
			return;
		}
		
		SpringEntityMappings mappings = new SpringEntityMappings(rootDirectory);
		
		for (File file: controllerFiles) {
			if (file != null && file.exists() && file.isFile() && file.getAbsolutePath() != null &&
					file.getAbsolutePath().contains(rootDirectory.getAbsolutePath())) {
				
				String fileNameWithoutRoot = FilePathUtils.getRelativePath(file, rootDirectory);
				
				if (fileNameWithoutRoot.indexOf("/") != 0) {
					fileNameWithoutRoot = "/" + fileNameWithoutRoot;
				}
				
				Set<SpringControllerEndpoint> endpoints = SpringControllerEndpointParser.parse(file, mappings);
				
				for (SpringControllerEndpoint endpoint : endpoints) {
					endpoint.setFileRoot(rootDirectory.getAbsolutePath());
					String urlPath = endpoint.getCleanedUrlPath();
					if (!urlToControllerMethodsMap.containsKey(urlPath)) {
						urlToControllerMethodsMap.put(urlPath, new TreeSet<SpringControllerEndpoint>());
					}
					urlToControllerMethodsMap.get(endpoint.getCleanedUrlPath()).add(endpoint);
				}

				controllerToUrlsMap.put(fileNameWithoutRoot, endpoints);
			}
		}
	}

	@Override
	public List<Endpoint> generateEndpoints() {
		List<Endpoint> returnEndpoints = new ArrayList<Endpoint>();
		
		for (Set<SpringControllerEndpoint> endpointList : urlToControllerMethodsMap.values()) {
			for (SpringControllerEndpoint endpoint : endpointList) {
				returnEndpoints.add(endpoint);
			}
		}
		
		return returnEndpoints;
	}
	
	@Override
	public String toString() {
		StringBuilder builder = new StringBuilder();
		
		for (Endpoint endpoint : generateEndpoints()) {
			builder.append(endpoint).append("\n");
		}
		
		return builder.toString();
	}
}
