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
package com.denimgroup.threadfix.framework.impl.spring;

import com.denimgroup.threadfix.XMLUtils;
import com.denimgroup.threadfix.data.interfaces.Endpoint;
import com.denimgroup.threadfix.exception.RestIOException;
import com.denimgroup.threadfix.framework.engine.full.EndpointGenerator;
import com.denimgroup.threadfix.framework.filefilter.FileExtensionFileFilter;
import com.denimgroup.threadfix.framework.impl.spring.auth.InterceptUrl;
import com.denimgroup.threadfix.framework.impl.spring.auth.SpringSecurityXmlParser;
import com.denimgroup.threadfix.framework.util.EventBasedTokenizerRunner;
import com.denimgroup.threadfix.framework.util.FilePathUtils;
import com.denimgroup.threadfix.framework.util.java.EntityMappings;
import com.denimgroup.threadfix.framework.util.java.EntityParser;
import com.denimgroup.threadfix.logging.SanitizedLogger;
import org.apache.commons.io.FileUtils;
import org.apache.commons.io.filefilter.TrueFileFilter;

import javax.annotation.Nonnull;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.util.*;

import static com.denimgroup.threadfix.CollectionUtils.*;
import static com.denimgroup.threadfix.data.entities.AuthenticationRequired.ANONYMOUS;
import static com.denimgroup.threadfix.data.entities.AuthenticationRequired.AUTHENTICATED;

public class SpringControllerMappings implements EndpointGenerator {
	
	@Nonnull
    private final Collection<File> javaFiles;
	@Nonnull
    private final Collection<File> xmlFiles;

    private static final SanitizedLogger LOG = new SanitizedLogger(SpringControllerMappings.class);
	
	@Nonnull
    private final Map<String, Set<SpringControllerEndpoint>>
            urlToControllerMethodsMap, controllerToUrlsMap;
	
	@Nonnull
    private final File rootDirectory;

    @Nonnull
    private List<SpringControllerEndpoint> endpointsList = list();
	
	@SuppressWarnings("unchecked")
	public SpringControllerMappings(@Nonnull File rootDirectory) {
		this.rootDirectory = rootDirectory;

        urlToControllerMethodsMap = map();
        controllerToUrlsMap = map();

		if (rootDirectory.exists()) {
			javaFiles = getFiles(rootDirectory, "java");
            xmlFiles  = getFiles(rootDirectory, "xml");
		    generateMaps();
		} else {
			javaFiles = Collections.emptyList();
            xmlFiles  = Collections.emptyList();
		}
	}

    private Collection<File> getFiles(File rootDirectory, String extension) {
        return FileUtils.listFiles(rootDirectory,
                new FileExtensionFileFilter(extension), TrueFileFilter.INSTANCE);
    }

    @Nonnull
	public Set<SpringControllerEndpoint> getEndpointsFromController(String controllerPath) {
		if (controllerToUrlsMap.containsKey(controllerPath)) {
			return controllerToUrlsMap.get(controllerPath);
		} else {
			return set();
		}
	}

    @Nonnull
	public Set<SpringControllerEndpoint> getEndpointsFromUrl(String controllerPath) {
		if (urlToControllerMethodsMap.containsKey(controllerPath)) {
			return urlToControllerMethodsMap.get(controllerPath);
		} else {
			return set();
		}
	}
	
	private void generateMaps() {
        List<EntityParser> entityParsers = list();

        SpringDataBinderParser globalDataBinderParser = null;

        SpringSecurityXmlParser securityXmlParser = new SpringSecurityXmlParser();
        for (File file : xmlFiles) {
            if (file != null && file.exists() && file.isFile() &&
                    file.getAbsolutePath().contains(rootDirectory.getAbsolutePath())) {

                try {
                    XMLUtils.readSAXInput(securityXmlParser, "", new FileInputStream(file));

                    if (!securityXmlParser.urls.isEmpty() || securityXmlParser.prePostEnabled) {
                        break;
                    }

                } catch (FileNotFoundException e) {
                    // this shouldn't happen
                    LOG.error("This is an illegal code path. security.xml results won't be available", e);
                } catch (RestIOException e) {
                    LOG.error("Encountered XML parsing error while parsing file " + file.getAbsolutePath());
                }
            }
        }

		for (File file: javaFiles) {
			if (file != null && file.exists() && file.isFile() &&
					file.getAbsolutePath().contains(rootDirectory.getAbsolutePath())) {

                SpringControllerEndpointParser endpointParser = new SpringControllerEndpointParser(file.getAbsolutePath());
                EntityParser entityParser = new EntityParser();
                SpringDataBinderParser dataBinderParser = new SpringDataBinderParser();
                EventBasedTokenizerRunner.run(file, entityParser, endpointParser, dataBinderParser);

                entityParsers.add(entityParser);
                addEndpointsToMaps(file, endpointParser, dataBinderParser);

                if (dataBinderParser.isGlobal) {
                    globalDataBinderParser = dataBinderParser;
                }
			}
		}

        EntityMappings mappings = new EntityMappings(entityParsers);

        for (SpringControllerEndpoint endpoint : endpointsList) {
            for (InterceptUrl url : securityXmlParser.urls) {
                if (url.matches(endpoint.getUrlPath())) {
                    endpoint.getRequiredPermissions().add(url.role);
                }
            }
            endpoint.expandParameters(mappings, globalDataBinderParser);
            if (endpoint.getRequiredPermissions().contains("IS_AUTHENTICATED_ANONYMOUSLY")) {
                endpoint.setAuthenticationRequired(ANONYMOUS);
            } else if (!endpoint.getRequiredPermissions().isEmpty()) {
                endpoint.setAuthenticationRequired(AUTHENTICATED);
            }
        }
	}

    private String getFileName(File file) {
        String fileNameWithoutRoot = FilePathUtils.getRelativePath(file, rootDirectory);

        if (fileNameWithoutRoot != null && fileNameWithoutRoot.indexOf("/") != 0) {
            fileNameWithoutRoot = "/" + fileNameWithoutRoot;
        }

        return fileNameWithoutRoot;
    }

    private void addEndpointsToMaps(File file, SpringControllerEndpointParser endpointParser,
                                    SpringDataBinderParser dataBinderParser) {
        if (endpointParser.hasControllerAnnotation) {

            endpointsList.addAll(endpointParser.endpoints);

            for (SpringControllerEndpoint endpoint : endpointParser.endpoints) {
                endpoint.setFileRoot(rootDirectory.getAbsolutePath());
                endpoint.setDataBinderParser(dataBinderParser);
                String urlPath = endpoint.getCleanedUrlPath();
                if (!urlToControllerMethodsMap.containsKey(urlPath)) {
                    urlToControllerMethodsMap.put(urlPath, new TreeSet<SpringControllerEndpoint>());
                }
                urlToControllerMethodsMap.get(endpoint.getCleanedUrlPath()).add(endpoint);
            }

            controllerToUrlsMap.put(getFileName(file), endpointParser.endpoints);
        }
    }

	@Nonnull
    @Override
	public List<Endpoint> generateEndpoints() {
		List<Endpoint> returnEndpoints = list();
		
		for (Set<SpringControllerEndpoint> endpointList : urlToControllerMethodsMap.values()) {
			for (SpringControllerEndpoint endpoint : endpointList) {
				returnEndpoints.add(endpoint);
			}
		}
		
		return returnEndpoints;
	}
	
	@Nonnull
    @Override
	public String toString() {
		StringBuilder builder = new StringBuilder();
		
		for (Endpoint endpoint : generateEndpoints()) {
			builder.append(endpoint).append("\n");
		}
		
		return builder.toString();
	}

    @Override
    public Iterator<Endpoint> iterator() {
        return generateEndpoints().iterator();
    }
}
