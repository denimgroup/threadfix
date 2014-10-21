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
package com.denimgroup.threadfix.framework.engine.full;

import com.denimgroup.threadfix.data.enums.FrameworkType;
import com.denimgroup.threadfix.data.enums.InformationSourceType;
import com.denimgroup.threadfix.data.interfaces.Endpoint;
import com.denimgroup.threadfix.framework.engine.CodePoint;
import com.denimgroup.threadfix.framework.engine.cleaner.PathCleaner;
import com.denimgroup.threadfix.logging.SanitizedLogger;
import javax.annotation.Nonnull;
import javax.annotation.Nullable;

import java.util.*;

import static com.denimgroup.threadfix.CollectionUtils.list;

class GeneratorBasedEndpointDatabase implements EndpointDatabase {
	
	@Nonnull
    private final List<Endpoint> endpoints;

    @Nonnull
	private final PathCleaner pathCleaner;

    @Nonnull
	private final FrameworkType frameworkType;
	
	private final Map<String, Set<Endpoint>>
		dynamicMap = new HashMap<>(),
		staticMap  = new HashMap<>(),
		parameterMap = new HashMap<>(),
		httpMethodMap = new HashMap<>();
	
	protected final static SanitizedLogger log = new SanitizedLogger(GeneratorBasedEndpointDatabase.class);

	public GeneratorBasedEndpointDatabase(@Nonnull EndpointGenerator endpointGenerator,
                                          @Nonnull PathCleaner pathCleaner,
                                          @Nonnull FrameworkType frameworkType) {
		
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
	
	private void addToMap(@Nonnull Map<String, Set<Endpoint>> map,
                          @Nonnull String value, @Nonnull Endpoint endpoint) {
        if (!map.containsKey(value)) {
            map.put(value, new HashSet<Endpoint>());
        }

        map.get(value).add(endpoint);
	}
	
	@Override
	public Endpoint findBestMatch(@Nonnull EndpointQuery query) {
		
		Endpoint returnEndpoint = null;
		
		Set<Endpoint> endpoints = findAllMatches(query);
		
		if (!endpoints.isEmpty()) {
			returnEndpoint = endpoints.iterator().next();
		}
		
		return returnEndpoint;
	}

	@Nonnull
    @Override
	public Set<Endpoint> findAllMatches(@Nonnull EndpointQuery query) {
		Set<Endpoint> resultingSet = new HashSet<>();

        List<Set<Endpoint>> resultSets = list();
        boolean assignedInitial = false;

        boolean useStatic = query.getStaticPath() != null &&
        		query.getInformationSourceType() == InformationSourceType.STATIC;

        List<CodePoint> codePoints = query.getCodePoints();
        if (codePoints != null && !codePoints.isEmpty()) {
            resultingSet = getFromCodePoints(codePoints);
            if (!resultingSet.isEmpty()) {
                assignedInitial = true;
            }
        }

        if (!useStatic && query.getDynamicPath() != null) {
            String cleaned = pathCleaner.cleanDynamicPath(query.getDynamicPath());
            resultSets.add(getValueOrEmptySet(cleaned, dynamicMap));
        }

        if (useStatic && query.getStaticPath() != null) {
            String cleaned = pathCleaner.cleanStaticPath(query.getStaticPath());
            resultSets.add(getValueOrEmptySet(cleaned, staticMap));
        }

        if (query.getHttpMethod() != null) {
            resultSets.add(getValueOrEmptySetWithSimpleKey(query.getHttpMethod(), httpMethodMap));
        }

        if (resultSets.size() > 0) {
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

        if (query.getParameter() != null) {
            Set<Endpoint> parameterEndpoints =
                    getValueOrEmptySetWithSimpleKey(query.getParameter(), parameterMap);

            // dynamic scan with a parameter that doesn't match any code is probably a false positive
            // this code will just ignore the parameter lookup for now.
            // TODO deal with false positives in a more effective manner
            if (useStatic || !parameterEndpoints.isEmpty()) {

                // doing blanket retainAll can lead to false negatives in some cases
                for (Endpoint parameterEndpoint : parameterEndpoints) {
                    if (resultingSet.contains(parameterEndpoint)) {
                        resultingSet.retainAll(parameterEndpoints);
                        break;
                    }
                }
            }
        }

		return resultingSet;
	}

    @Nonnull
    private Set<Endpoint> getFromCodePoints(@Nonnull List<CodePoint> codePoints) {
        Set<Endpoint> results = new HashSet<>();

        top: for (CodePoint codePoint : codePoints) {
            if (codePoint != null) {
                String sourceFileKey = null;

                String sourceFileName = codePoint.getSourceFileName();

                if (sourceFileName != null) {
                    String cleanedSourceFileName = pathCleaner.cleanStaticPath(sourceFileName);
                    for (String key : staticMap.keySet()) {
                        if (key.endsWith(sourceFileName) ||
                                (cleanedSourceFileName != null && key.endsWith(cleanedSourceFileName))) {
                            sourceFileKey = key;
                        }
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

    @Nonnull
    private Set<Endpoint> getValueOrEmptySet(@Nullable String key,
                                             @Nonnull Map<String, Set<Endpoint>> map) {
        if (key == null)
            return new HashSet<>();

        String keyForwardSlash = key.replace("\\","/");

        for (Map.Entry<String,Set<Endpoint>> entry: map.entrySet()) {
            String keyEntry = entry.getKey();
            String keyEntryForwardSlash = keyEntry.replace("\\","/");

            if ((keyEntry.isEmpty() && !key.isEmpty())
                    || (key.isEmpty() && !keyEntry.isEmpty()))
                return new HashSet<>();

            if (keyEntryForwardSlash.endsWith(keyForwardSlash) || keyForwardSlash.endsWith(keyEntryForwardSlash))
                return new HashSet<>(entry.getValue());
        }

        return new HashSet<>();
    }

	@Nonnull
    private Set<Endpoint> getValueOrEmptySetWithSimpleKey(@Nullable String key,
                                             @Nonnull Map<String, Set<Endpoint>> map) {
		if (key != null && map.containsKey(key) && map.get(key) != null) {
			return new HashSet<>(map.get(key));
		} else {
			return new HashSet<>();
		}
	}

	@Nonnull
    @Override
	public List<Endpoint> generateEndpoints() {
		return endpoints;
	}

	@Nonnull
    @Override
	public FrameworkType getFrameworkType() {
		return frameworkType;
	}

	@Nonnull
    @Override
	public String toString() {
		return frameworkType.toString() + " EndpointDatabase with " + endpoints.size() + " total records.";
	}

    @Override
    public Iterator<Endpoint> iterator() {
        return endpoints.iterator();
    }
}
