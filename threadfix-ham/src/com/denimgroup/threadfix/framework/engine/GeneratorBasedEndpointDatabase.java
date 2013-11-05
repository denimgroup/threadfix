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
package com.denimgroup.threadfix.framework.engine;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import com.denimgroup.threadfix.framework.beans.PathCleaner;
import com.denimgroup.threadfix.framework.enums.FrameworkType;
import com.denimgroup.threadfix.framework.util.SanitizedLogger;

public class GeneratorBasedEndpointDatabase implements EndpointDatabase {
	
	private final List<Endpoint> endpoints;
	private final PathCleaner pathCleaner;
	private final FrameworkType frameworkType;
	
	private final Map<String, Set<Endpoint>>
		dynamicMap = new HashMap<>(),
		staticMap  = new HashMap<>(),
		httpMethodMap = new HashMap<>();
	
	protected final static SanitizedLogger log = new SanitizedLogger(GeneratorBasedEndpointDatabase.class);

	public GeneratorBasedEndpointDatabase(EndpointGenerator endpointGenerator,
			PathCleaner pathCleaner,
			FrameworkType frameworkType) {
		
		log.info("Using generic EndpointGenerator-based translator.");
		
		if (endpointGenerator != null) {
			endpoints = endpointGenerator.generateEndpoints();
		} else {
			endpoints = new ArrayList<Endpoint>();
		}
		
		this.frameworkType = frameworkType;
		this.pathCleaner = pathCleaner;
		
		buildMappings();
	}

	private void buildMappings() {
		log.info("Building mappings.");
		for (Endpoint endpoint : endpoints) {
			addToMap(dynamicMap, endpoint.getUrlPath(), endpoint);
			addToMap(staticMap, endpoint.getFilePath(), endpoint);
			
			for (String method : endpoint.getHttpMethods()) {
				addToMap(httpMethodMap, method, endpoint);
				
				if (!"POST".equals(method) && !"GET".equals(method)) {
					addToMap(httpMethodMap, "POST", endpoint);
				}
			}
		}
		log.info("Done building mappings. Static keys: " + staticMap.size() + ", dynamic keys: " + dynamicMap.size());
	}
	
	private void addToMap(Map<String, Set<Endpoint>> map, String value, Endpoint endpoint) {
		if (endpoint != null && value != null) {
			if (!map.containsKey(value)) {
				map.put(value, new HashSet<Endpoint>());
			}
			
			map.get(value).add(endpoint);
		}
	}

	@Override
	public Endpoint findBestMatch(EndpointQuery query) {
		Endpoint returnEndpoint = null;
		
		Set<Endpoint> endpoints = findAllMatches(query);
		
		if (!endpoints.isEmpty()) {
			returnEndpoint = endpoints.iterator().next();
		}
		
		return returnEndpoint;
	}

	@Override
	public Set<Endpoint> findAllMatches(EndpointQuery query) {
		Set<Endpoint> resultingSet = new HashSet<>();
		
		if (query != null) {
			List<Set<Endpoint>> resultSets = new ArrayList<>();
			
			if (query.getDynamicPath() != null) {
				resultSets.add(getValueOrNull(pathCleaner.cleanDynamicPath(query.getDynamicPath()), dynamicMap));
			}
			
			if (query.getStaticPath() != null) {
				resultSets.add(getValueOrNull(pathCleaner.cleanStaticPath(query.getStaticPath()), staticMap));
			}
			
			if (query.getHttpMethod() != null) {
				resultSets.add(getValueOrNull(query.getHttpMethod(), httpMethodMap));
			}
			
			if (resultSets.size() > 0) {
				Set<Endpoint> union = null;
				
				for (Set<Endpoint> endpoints : resultSets) {
					if (union == null) {
						union = endpoints;
					}
					
					union.retainAll(endpoints);
				}
				
				resultingSet = union;
			}
		}

		return resultingSet;
	}
	
	private Set<Endpoint> getValueOrNull(String key, Map<String, Set<Endpoint>> map) {
		if (map.containsKey(key) && map.get(key) != null) {
			return new HashSet<>(map.get(key));
		} else {
			return new HashSet<>();
		}
	}

	@Override
	public List<Endpoint> generateEndpoints() {
		return endpoints;
	}

	@Override
	public FrameworkType getFrameworkType() {
		return frameworkType;
	}

	public String toString() {
		return frameworkType.toString() + " EndpointDatabase with " + endpoints.size() + " total records.";
	}
	
}
