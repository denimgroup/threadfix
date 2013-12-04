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
package com.denimgroup.threadfix.framework.engine.full;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import com.denimgroup.threadfix.framework.engine.CodePoint;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

import com.denimgroup.threadfix.framework.engine.cleaner.PathCleaner;
import com.denimgroup.threadfix.framework.enums.FrameworkType;
import com.denimgroup.threadfix.framework.enums.InformationSourceType;
import com.denimgroup.threadfix.framework.util.SanitizedLogger;

class GeneratorBasedEndpointDatabase implements EndpointDatabase {
	
	@NotNull
    private final List<Endpoint> endpoints;

    @NotNull
	private final PathCleaner pathCleaner;

    @NotNull
	private final FrameworkType frameworkType;
	
	private final Map<String, Set<Endpoint>>
		dynamicMap = new HashMap<>(),
		staticMap  = new HashMap<>(),
		parameterMap = new HashMap<>(),
		httpMethodMap = new HashMap<>();
	
	protected final static SanitizedLogger log = new SanitizedLogger(GeneratorBasedEndpointDatabase.class);

	public GeneratorBasedEndpointDatabase(@NotNull EndpointGenerator endpointGenerator,
                                          @NotNull PathCleaner pathCleaner,
                                          @NotNull FrameworkType frameworkType) {
		
		log.info("Using generic EndpointGenerator-based translator.");
		
        endpoints = endpointGenerator.generateEndpoints();

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
				
				// If non-standard methods are used, add post because that's what scanners might have
				if (!"POST".equals(method) && !"GET".equals(method)) {
					addToMap(httpMethodMap, "POST", endpoint);
				}
			}
			
			if (endpoint.getParameters().isEmpty()) {
				addToMap(parameterMap, "null", endpoint);
			} else {
				for (String parameter : endpoint.getParameters()) {
					addToMap(parameterMap, parameter, endpoint);
				}
			}
		}
		log.info("Done building mappings. Static keys: " + staticMap.size() + ", dynamic keys: " + dynamicMap.size());
	}
	
	private void addToMap(@NotNull Map<String, Set<Endpoint>> map,
                          @NotNull String value, @NotNull Endpoint endpoint) {
        if (!map.containsKey(value)) {
            map.put(value, new HashSet<Endpoint>());
        }

        map.get(value).add(endpoint);
	}
	
	@Override
	public Endpoint findBestMatch(@NotNull EndpointQuery query) {
		
		Endpoint returnEndpoint = null;
		
		Set<Endpoint> endpoints = findAllMatches(query);
		
		if (!endpoints.isEmpty()) {
			returnEndpoint = endpoints.iterator().next();
		}
		
		return returnEndpoint;
	}

	@NotNull
    @Override
	public Set<Endpoint> findAllMatches(@NotNull EndpointQuery query) {
		Set<Endpoint> resultingSet = new HashSet<>();
		
        List<Set<Endpoint>> resultSets = new ArrayList<>();
        
        boolean useStatic = query.getStaticPath() != null &&
        		query.getInformationSourceType() == InformationSourceType.STATIC;

        if (!useStatic && query.getDynamicPath() != null) {
            String cleaned = pathCleaner.cleanDynamicPath(query.getDynamicPath());
            resultSets.add(getValueOrEmptySet(cleaned, dynamicMap));
        }

        if (useStatic && query.getStaticPath() != null) {
            String cleaned = pathCleaner.cleanStaticPath(query.getStaticPath());
            resultSets.add(getValueOrEmptySet(cleaned, staticMap));
        }

        if (query.getHttpMethod() != null) {
            resultSets.add(getValueOrEmptySet(query.getHttpMethod(), httpMethodMap));
        }

        if (query.getParameter() != null) {
            resultSets.add(getValueOrEmptySet(query.getParameter(), parameterMap));
        }

        if (resultSets.size() > 0) {
            boolean assignedInitial = false;

            for (Set<Endpoint> endpoints : resultSets) {
                if (endpoints != null) {

                    if (!assignedInitial) {
                        resultingSet = endpoints;
                        assignedInitial = true;
                    }

                    resultingSet.retainAll(endpoints);
                }
            }
        }

        if (resultingSet.isEmpty() && query.getCodePoints() != null) {
            resultingSet = getFromCodePoints(query.getCodePoints());
        }

		return resultingSet;
	}

    @NotNull
    private Set<Endpoint> getFromCodePoints(@NotNull List<CodePoint> codePoints) {
        Set<Endpoint> results = new HashSet<>();

        top: for (CodePoint codePoint : codePoints) {
            if (codePoint != null && codePoint.getSourceFileName() != null) {
                String sourceFileKey = null;

                for (String key : staticMap.keySet()) {
                    if (key.endsWith(codePoint.getSourceFileName())) {
                        sourceFileKey = key;
                    }
                }

                if (sourceFileKey != null) {
                    Set<Endpoint> innerResult = getValueOrEmptySet(sourceFileKey, staticMap);

                    for (Endpoint endpoint : innerResult) {
                        if (endpoint != null && endpoint.matchesLineNumber(codePoint.getLineNumber())) {
                            results.add(endpoint);
                            break top;
                        }
                    }
                }
            }
        }

        return results;
    }
	
	@NotNull
    private Set<Endpoint> getValueOrEmptySet(@Nullable String key,
                                             @NotNull Map<String, Set<Endpoint>> map) {
		if (key != null && map.containsKey(key) && map.get(key) != null) {
			return new HashSet<>(map.get(key));
		} else {
			return new HashSet<>();
		}
	}

	@NotNull
    @Override
	public List<Endpoint> generateEndpoints() {
		return endpoints;
	}

	@NotNull
    @Override
	public FrameworkType getFrameworkType() {
		return frameworkType;
	}

	@NotNull
    @Override
	public String toString() {
		return frameworkType.toString() + " EndpointDatabase with " + endpoints.size() + " total records.";
	}
	
}
