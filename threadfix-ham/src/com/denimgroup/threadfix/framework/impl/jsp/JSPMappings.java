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
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.apache.commons.io.FileUtils;

import com.denimgroup.threadfix.framework.engine.full.Endpoint;
import com.denimgroup.threadfix.framework.engine.full.EndpointGenerator;
import com.denimgroup.threadfix.framework.filefilter.NoDotDirectoryFileFilter;
import com.denimgroup.threadfix.framework.util.CommonPathFinder;
import com.denimgroup.threadfix.framework.util.FilePathUtils;

// TODO figure out HTTP methods perhaps from form analysis
// for now all will be GET
public class JSPMappings implements EndpointGenerator {
	
	private final Map<String, Set<File>> includeMap = new HashMap<>();
	private final Map<String, Map<Integer, List<String>>> parameterMap = new HashMap<>();
	private final List<Endpoint> endpoints = new ArrayList<>();
	private final File projectRoot, jspRoot;
	
	@SuppressWarnings("unchecked")
	public JSPMappings(File rootFile) {
		if (rootFile != null && rootFile.exists()) {

			this.projectRoot = rootFile;
			
			String jspRootString = CommonPathFinder.findOrParseProjectRootFromDirectory(rootFile, "jsp");
			
			if (jspRootString == null) {
				jspRoot = projectRoot;
			} else {
				jspRoot = new File(jspRootString);
			}
			
			Collection<File> jspFiles = FileUtils.listFiles(
					rootFile, JSPFileFilter.INSTANCE, NoDotDirectoryFileFilter.INSTANCE);
	
			for (File file : jspFiles) {
				Set<File> files = JSPIncludeParser.parse(file);
				if (files != null && !files.isEmpty()) {
					includeMap.put(FilePathUtils.getRelativePath(file, rootFile), files);
				}
			}
			
			for (File file : jspFiles) {
				Endpoint endpoint = getEndpoint(file);
				if (endpoint != null) {
					endpoints.add(endpoint);
				}
			}
		} else {
			projectRoot = null;
			jspRoot = null;
		}
	}
	
	public Endpoint getEndpoint(File file) {
		Endpoint endpoint = null;
		
		Map<Integer, List<String>> parserResults = JSPParameterParser.parse(file);
		if (parserResults != null) {
			parameterMap.put(FilePathUtils.getRelativePath(file, projectRoot), parserResults);
			Set<String> allParameters = new HashSet<>();
			for (List<String> parameters : parserResults.values()) {
				allParameters.addAll(parameters);
			}
			endpoint = new JSPEndpoint(
					FilePathUtils.getRelativePath(file, projectRoot),
					FilePathUtils.getRelativePath(file, jspRoot),
					allParameters,
					new HashSet<String>(Arrays.asList("GET", "POST"))
					);
		}
		
		return endpoint;
	}
	
	public Set<File> getIncludedFiles(String relativePath) {
		return includeMap.get(relativePath);
	}
	
	public Map<Integer, List<String>> getParameterMap(String relativePath) {
		return parameterMap.get(relativePath);
	}
	
	// TODO simple optimizations to clean up the code and make it more efficient
	// create a map of parameter name to first line when this class is initialized and do lookups on that
	// it should be O(n) on the map and then O(1) instead of O(N) every time
	public Integer getFirstLineNumber(String relativeFilePath, String parameterName) {
		Map<Integer, List<String>> parameterMap = getParameterMap(relativeFilePath);
		
		Integer returnValue = Integer.MAX_VALUE;
		
		if (parameterMap != null && parameterName != null) {
			for (Integer integer : parameterMap.keySet()) {
				if (integer < returnValue &&
						parameterMap.get(integer) != null &&
						parameterMap.get(integer).contains(parameterName)) {
					returnValue = integer;
				}
			}
		}
		
		if (returnValue == Integer.MAX_VALUE) {
			returnValue = 1; // This way even if no parameter is found a marker can be created for the file
		}
		
		return returnValue;
	}
	
	public String getRelativePath(String dataFlowLocation) {
		return FilePathUtils.getRelativePath(dataFlowLocation, projectRoot);
	}

	@Override
	public List<Endpoint> generateEndpoints() {
		return endpoints;
	}
}
