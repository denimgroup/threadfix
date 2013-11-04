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
package com.denimgroup.threadfix.service.translator;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import com.denimgroup.threadfix.data.entities.Application;
import com.denimgroup.threadfix.data.entities.DataFlowElement;
import com.denimgroup.threadfix.data.entities.Finding;
import com.denimgroup.threadfix.data.entities.Scan;
import com.denimgroup.threadfix.framework.engine.Endpoint;
import com.denimgroup.threadfix.framework.enums.FrameworkType;
import com.denimgroup.threadfix.framework.enums.SourceCodeAccessLevel;
import com.denimgroup.threadfix.framework.impl.spring.SpringControllerEndpoint;
import com.denimgroup.threadfix.framework.impl.spring.SpringControllerMappings;
import com.denimgroup.threadfix.framework.util.CommonPathFinder;
import com.denimgroup.threadfix.service.merge.ScanMergeConfiguration;

public class SpringMVCTranslator extends AbstractPathUrlTranslator {
	
	private SpringControllerMappings fullMappings = null;
	
	public static final String JSESSIONID = ";jsessionid=";
	
	/**
	 * This map is canonical url path -> canonical file path
	 */
	private Map<String, String> partialMappings = null;

	public SpringMVCTranslator(ScanMergeConfiguration scanMergeConfiguration, Scan scan) {
		super(scanMergeConfiguration, scan);
		
		log.info("Using Spring MVC URL - Path translator.");
		
		SourceCodeAccessLevel accessLevel = scanMergeConfiguration.getSourceCodeAccessLevel();
		
		// TODO update these
		filePathRoot = CommonPathFinder.findOrParseProjectRoot(scan.toPartialMappingList());
		urlPathRoot  = CommonPathFinder.findOrParseUrlPath(scan.toPartialMappingList());
		
		if (scan != null) {
			scan.setFilePathRoot(filePathRoot);
			scan.setUrlPathRoot(urlPathRoot);
		}
		
		switch (accessLevel) {
			case FULL:    buildFullSourceMappings();    break;
			case PARTIAL: buildPartialSourceMappings(); break;
			default: // don't care, just do basic matching
		}
	}

	private void buildPartialSourceMappings() {
		log.info("Attempting to build Spring mappings from partial source.");
		
		boolean addedMappings = false;
		
		partialMappings = new HashMap<>();
		
		if (scan != null && scan.isStatic()) {
			addedMappings = true;
			addStaticMappings(scan);
		}
		
		Application application = scanMergeConfiguration.getApplication();
		
		if (application != null && application.getScans() != null) {
			for (Scan applicationScan : application.getScans()) {
				if (applicationScan.isStatic()) {
					addedMappings = true;
					addStaticMappings(applicationScan);
				}
			}
		}
		
		if (addedMappings) {
			log.info("Successfully built mappings from partial source.");
		} else {
			log.error("No partial source found, so no mappings could be parsed.");
		}
	}
	
	private void buildFullSourceMappings() {
		if (workTree != null && workTree.exists()) {
			log.info("Building mappings from full source.");
			fullMappings = new SpringControllerMappings(workTree);
		} else {
			log.error("Attempted to build mappings from nonexistent source. " +
					"Please configure a repository URL correctly.");
		}
	}

	// this implementation is for partial source access
	private void addStaticMappings(Scan scan) {
		if (scan != null && scan.getFindings() != null) {
			for (Finding finding : scan.getFindings()) {
				if (finding != null && finding.getStaticPathInformation() != null &&
						finding.getStaticPathInformation().guessFrameworkType() == FrameworkType.SPRING_MVC) {
					String standardizedUrl =
							SpringControllerEndpoint.cleanUrlPathStatic(finding.getStaticPathInformation().getValue());
					
					// TODO look into whether or not we need to extract information from data flows
					partialMappings.put(standardizedUrl, finding.getSourceFileLocation());
				}
			}
		}
	}

	// TODO utilize source code and find a common root, similar to DefaultTranslator
	@Override
	public String getFileName(Finding finding) {
		
		String fileName = null;
		
		if (projectDirectory != null && finding.getIsStatic() && finding.getSourceFileLocation() != null) {
			fileName = projectDirectory.findCanonicalFilePath(
					finding.getSourceFileLocation(), applicationRoot);
		} else {
			switch (scanMergeConfiguration.getSourceCodeAccessLevel()) {
				case FULL:    fileName = getFilePathFullSource(finding); break;
				case PARTIAL: fileName = getFilePathPartial(finding);    break;
				default: // return null, it's ok to not predict a controller with no source
			}
		}
		
		return fileName;
	}

	private String getFilePathPartial(Finding finding) {
		String filePath = null;
		
		String canonicalUrlPath = getUrlPath(finding);
		if (partialMappings != null && canonicalUrlPath != null &&
				partialMappings.get(canonicalUrlPath) != null) {
			filePath = partialMappings.get(canonicalUrlPath);
		}
		
		return filePath;
	}

	private String getFilePathFullSource(Finding finding) {
		String filePath = null;
		
		String httpMethod = null;
		if (finding.getSurfaceLocation() != null) {
			httpMethod = finding.getSurfaceLocation().getHttpMethod();
		}
		
		String canonicalUrlPath = getUrlPath(finding);
		if (fullMappings != null && canonicalUrlPath != null) {
			
			Set<SpringControllerEndpoint> endpoints =
					fullMappings.getEndpointsFromUrl(canonicalUrlPath);
			
			if (endpoints != null && !endpoints.isEmpty()) {
				for (SpringControllerEndpoint endpoint : endpoints) {
					if (httpMethod == null || endpoint.matchesMethod(httpMethod)) {
						filePath = endpoint.getCleanedFilePath();
						finding.setEntryPointLineNumber(endpoint.getStartLineNumber());
						break;
					}
				}
			}
		}
		
		return filePath;
	}

	@Override
	public String getUrlPath(Finding finding) {
		String urlPath = null;
		
		if (finding != null) {
			if (finding.getIsStatic()) {
				switch (scanMergeConfiguration.getSourceCodeAccessLevel()) {
					case FULL:    urlPath = getUrlPathFullSource(finding); break;
					case PARTIAL: urlPath = getUrlPathPartial(finding);    break;
					default: // return null, it's fine (we shouldn't even get here)
				}
			} else {
				if (finding.getSurfaceLocation() != null) {
					urlPath = SpringControllerEndpoint.cleanUrlPathDynamic(finding.getSurfaceLocation().getPath());
					if (urlPath != null && urlPathRoot != null && urlPath.contains(urlPathRoot)) {
						urlPath = urlPath.replace(urlPathRoot, "");
					}
				}
			}
		}
		
		if (urlPath.contains(JSESSIONID)) {
			urlPath = urlPath.substring(0, urlPath.indexOf(JSESSIONID));
		}

		return urlPath;
	}

	private String getUrlPathPartial(Finding finding) {
		if (finding.getStaticPathInformation() != null &&
				finding.getStaticPathInformation().guessFrameworkType() == FrameworkType.SPRING_MVC) {
			return SpringControllerEndpoint.cleanUrlPathStatic(finding.getStaticPathInformation().getValue());
		} else {
			// TODO look through data flows for matches to the partialMappings map
			return null;
		}
	}

	private String getUrlPathFullSource(Finding staticFinding) {
		String urlPath = null;
		
		if (projectDirectory != null && staticFinding != null && staticFinding.getDataFlowElements() != null) {
			
			DFE: for (DataFlowElement dataFlowElement : staticFinding.getDataFlowElements()) {
				String fileName = projectDirectory.findCanonicalFilePath(
						dataFlowElement.getSourceFileName(), applicationRoot);
				
				if (fileName != null && fileName.length() > 0 && fileName.charAt(0) != '/') {
					fileName = "/" + fileName;
				}
				
				if (fileName != null && !fullMappings.getEndpointsFromController(fileName).isEmpty()) {
					Set<SpringControllerEndpoint> endpoints = fullMappings.getEndpointsFromController(fileName);
					
					for (SpringControllerEndpoint endpoint : endpoints) {
						if (endpoint.matchesLineNumber(dataFlowElement.getLineNumber())) {
							urlPath = endpoint.getCleanedUrlPath();
							break DFE;
						}
					}
				}
			}
		}
		
		return urlPath;
	}

	@Override
	public List<Endpoint> generateEndpoints() {
		return fullMappings.generateEndpoints();
	}
	
}
