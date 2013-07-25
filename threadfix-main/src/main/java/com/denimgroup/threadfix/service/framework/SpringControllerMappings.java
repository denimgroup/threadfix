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
package com.denimgroup.threadfix.service.framework;

import java.io.File;
import java.util.Collection;
import java.util.HashMap;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Set;

import org.apache.commons.io.FileUtils;
import org.apache.commons.io.filefilter.TrueFileFilter;

public class SpringControllerMappings {
	
	// test code for petclinic
	public static void main(String[] args) {
		File file = new File("C:\\test\\projects\\spring-petclinic");
		
		SpringControllerMappings mappings = new SpringControllerMappings(file);
		
		for (Entry<String, SpringControllerEndpoint> entry : mappings.urlToControllerMap.entrySet()) {
			entry.getValue().setFileRoot("C:\\test\\projects\\spring-petclinic");
			System.out.println(entry);
		}
	}
	
	public final Collection<File> controllerFiles;
	
	public final Map<String, SpringControllerEndpoint> urlToControllerMap;
	public final Map<String, Set<SpringControllerEndpoint>> controllerToUrlsMap;
	
	public final File rootDirectory;
	
	@SuppressWarnings("unchecked")
	public SpringControllerMappings(File rootDirectory) {
		this.rootDirectory = rootDirectory;
		if (rootDirectory != null && rootDirectory.exists()) {
			controllerFiles = FileUtils.listFiles(rootDirectory, new SpringControllerFileFilter(), TrueFileFilter.INSTANCE);
		
			urlToControllerMap = new HashMap<>();
			controllerToUrlsMap = new HashMap<>();
			
			if (controllerFiles != null) {
				generateMaps();
			}
		} else {
			controllerFiles = null;
			urlToControllerMap = null;
			controllerToUrlsMap = null;
		}
	}
	
	private void generateMaps() {
		if (controllerFiles == null || 
				urlToControllerMap == null || 
				controllerToUrlsMap == null) {
			return;
		}
		
		for (File file: controllerFiles) {
			if (file != null && file.exists() && file.isFile() && file.getAbsolutePath() != null && 
					file.getAbsolutePath().contains(rootDirectory.getAbsolutePath())) {
				
				String fileNameWithoutRoot = file.getAbsolutePath().substring(rootDirectory.getAbsolutePath().length());
				
				Set<SpringControllerEndpoint> endpoints = SpringControllerEndpointParser.parseEndpoints(file);
				
				for (SpringControllerEndpoint endpoint : endpoints) {
					endpoint.setFileRoot(rootDirectory.getAbsolutePath());
					urlToControllerMap.put(endpoint.getCleanedUrlPath(), endpoint);
				}

				controllerToUrlsMap.put(fileNameWithoutRoot, endpoints);
			}
		}
	}
}
