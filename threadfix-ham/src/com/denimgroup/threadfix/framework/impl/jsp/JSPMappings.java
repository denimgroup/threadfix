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
	private final Map<String, JSPEndpoint> jspEndpointMap = new HashMap<>();
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
		JSPEndpoint endpoint = null;
		
		Map<Integer, List<String>> parserResults = JSPParameterParser.parse(file);
		if (parserResults != null) {
			String staticPath = FilePathUtils.getRelativePath(file, projectRoot);
			
			endpoint = new JSPEndpoint(
					staticPath,
					FilePathUtils.getRelativePath(file, jspRoot),
					new HashSet<String>(Arrays.asList("GET", "POST")),
					parserResults
					);
			
			jspEndpointMap.put(staticPath, endpoint);
		}
		
		return endpoint;
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

	@Override
	public List<Endpoint> generateEndpoints() {
		return endpoints;
	}
}
