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
package com.denimgroup.threadfix.framework.impl.jsp;

import java.io.File;
import java.util.*;

import com.denimgroup.threadfix.framework.engine.ProjectDirectory;
import com.denimgroup.threadfix.framework.util.EventBasedTokenizerRunner;
import com.denimgroup.threadfix.logging.SanitizedLogger;
import org.apache.commons.io.FileUtils;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

import com.denimgroup.threadfix.data.interfaces.Endpoint;
import com.denimgroup.threadfix.framework.engine.full.EndpointGenerator;
import com.denimgroup.threadfix.framework.filefilter.NoDotDirectoryFileFilter;
import com.denimgroup.threadfix.framework.util.CommonPathFinder;
import com.denimgroup.threadfix.framework.util.FilePathUtils;

// TODO figure out HTTP methods perhaps from form analysis
public class JSPMappings implements EndpointGenerator {
	
	private static final SanitizedLogger LOG = new SanitizedLogger("JSPMappings");
	
	private final Map<String, Set<String>> includeMap = new HashMap<>();
	private final Map<String, JSPEndpoint> jspEndpointMap = new HashMap<>();
	private final List<Endpoint> endpoints = new ArrayList<>();
    private final ProjectDirectory projectDirectory;
	@Nullable
    private final File projectRoot, jspRoot;
	
	@SuppressWarnings("unchecked")
	public JSPMappings(@NotNull File rootFile) {
		if (rootFile.exists()) {

			this.projectRoot = rootFile;

            projectDirectory = new ProjectDirectory(rootFile);
			
			String jspRootString = CommonPathFinder.findOrParseProjectRootFromDirectory(rootFile, "jsp");

            LOG.info("Calculated JSP root to be: " + jspRootString);
			
			if (jspRootString == null) {
				jspRoot = projectRoot;
			} else {
				jspRoot = new File(jspRootString);
			}
			
			Collection<File> jspFiles = FileUtils.listFiles(
					rootFile, JSPFileFilter.INSTANCE, NoDotDirectoryFileFilter.INSTANCE);

            LOG.info("Found " + jspFiles.size() + " JSP files.");

			for (File file : jspFiles) {
				parseFile(file);
			}

            addParametersFromIncludedFiles();

		} else {
            projectDirectory = null;
			projectRoot = null;
			jspRoot = null;
		}
	}
	
    void parseFile(File file) {

        if (projectRoot != null) {
            // we will use both parsers on the same run through the file
            String staticPath = FilePathUtils.getRelativePath(file, projectRoot);

            JSPIncludeParser includeParser = new JSPIncludeParser(file);
            JSPParameterParser parameterParser = new JSPParameterParser();
            EventBasedTokenizerRunner.run(file, parameterParser, includeParser);

            addToIncludes(staticPath, includeParser.returnFiles);

            createEndpoint(staticPath, file, parameterParser.buildParametersMap());
        }
	}

    void createEndpoint(String staticPath, File file, Map<Integer, List<String>> parserResults) {
        JSPEndpoint endpoint = new JSPEndpoint(
                getInputOrEmptyString(staticPath),
                getInputOrEmptyString(FilePathUtils.getRelativePath(file, jspRoot)),
                new HashSet<>(Arrays.asList("GET", "POST")),
                parserResults
        );

        jspEndpointMap.put(staticPath, endpoint);

        endpoints.add(endpoint);
    }

    void addToIncludes(String staticPath, Set<File> includedFiles) {
        if (projectRoot != null && projectDirectory != null) {
            if (!includedFiles.isEmpty()) {
                Set<String> cleanedFilePaths = new HashSet<>();

                for (File file : includedFiles) {
                    String cleaned = projectDirectory.findCanonicalFilePath(file);
                    if (cleaned != null) {
                        cleanedFilePaths.add(cleaned);
                    }
                }

                includeMap.put(staticPath, cleanedFilePaths);
            }
        }
    }

    void addParametersFromIncludedFiles() {
        for (Map.Entry<String, JSPEndpoint> endpointEntry : jspEndpointMap.entrySet()) {
            if (endpointEntry != null && endpointEntry.getKey() != null &&
                    includeMap.get(endpointEntry.getKey()) != null) {
                for (String fileKey : includeMap.get(endpointEntry.getKey())) {
                    if (jspEndpointMap.containsKey(fileKey)) {
                        endpointEntry.getValue().getParameters().addAll(
                                jspEndpointMap.get(fileKey).getParameters());
                    }
                }
            }
        }
    }

    @NotNull
    private String getInputOrEmptyString(@Nullable String input) {
        return input == null ? "" : input;
    }
	
	public JSPEndpoint getEndpoint(String staticPath) {
		
		String key = staticPath; // TODO determine whether we need to clean or not
		
		if (key != null && !key.startsWith("/")) {
			key = "/" + key;
		}
		
		return jspEndpointMap.get(key);
	}
	
	public String getRelativePath(String dataFlowLocation) {
		return FilePathUtils.getRelativePath(dataFlowLocation, projectRoot);
	}

	@NotNull
    @Override
	public List<Endpoint> generateEndpoints() {
		return endpoints;
	}

    @Override
    public Iterator<Endpoint> iterator() {
        return endpoints.iterator();
    }
}
