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
import java.util.Arrays;

import com.denimgroup.threadfix.data.entities.Finding;
import com.denimgroup.threadfix.data.entities.Scan;
import com.denimgroup.threadfix.service.SanitizedLogger;
import com.denimgroup.threadfix.service.merge.ScanMergeConfiguration;
import com.denimgroup.threadfix.service.merge.SourceCodeAccessLevel;

public abstract class AbstractPathUrlTranslator implements PathUrlTranslator {
	
	protected String filePathRoot, urlPathRoot;
	
	private static Iterable<String> SUFFIXES = Arrays.asList("html", "htm", "cs");
	
	protected final ServletMappings mappings;
	protected final File workTree;
	protected final String applicationRoot;
	protected final ScanMergeConfiguration scanMergeConfiguration;
	protected final Scan scan;
	protected ProjectDirectory projectDirectory = null;
	
	protected final static SanitizedLogger log = new SanitizedLogger(AbstractPathUrlTranslator.class);
	
	/**
	 * @param scan
	 * @param mappings
	 * @param workTree
	 */
	public AbstractPathUrlTranslator(ScanMergeConfiguration configuration, Scan scan) {
		
		this.mappings = configuration.getServletMappings();
		this.workTree = configuration.getWorkTree();
		this.applicationRoot = "/" + configuration.getApplicationRoot();
		this.scanMergeConfiguration = configuration;
		this.scan = scan;
		
		if (scanMergeConfiguration.getSourceCodeAccessLevel() == SourceCodeAccessLevel.FULL) {
			if (workTree != null && workTree.exists()) {
				projectDirectory = new ProjectDirectory(workTree);
			} else {
				log.warn("Source Code Access Level was set to full but no files were found.");
			}
		}
		
		if (this.workTree == null || !this.workTree.exists()) {
			log.warn("Work tree doesn't exist.");
		}
	}
	
	protected final String getFileNameDefault(Finding finding) {
		String fileName = getLocationInformation(finding);
		
		if (fileName != null) {
			int index = containsIgnoreCase(fileName, filePathRoot);
				
			if (index != -1) {
				fileName = fileName.substring(index);
			}
			
			fileName = standardizeSlashes(fileName);
		}
		
		return fileName;
	}

	protected final String getUrlPathDefault(Finding finding) {
		String urlPath = getLocationInformation(finding);
		
		if (urlPath != null) {
			int index = containsIgnoreCase(urlPath, urlPathRoot);
			
			if (index != -1) {
				urlPath = urlPath.substring(index);
			}
			
			if (finding.getIsStatic()) {
				urlPath = cleanStaticUrlPath(urlPath);
			}
		}
			
		return urlPath;
	}
	
	protected Iterable<String> getSuffixVals() {
		return SUFFIXES;
	}
	
	// get the default piece of information for the finding
	// static -> file path, dynamic -> url path
	private String getLocationInformation(Finding finding) {
		String location = null;
		
		if (finding != null) {
			if (finding.getIsStatic()) {
				location = finding.getSourceFileLocation();
				if ((location == null || location.isEmpty()) &&
					finding.getDataFlowElements() != null &&
							!finding.getDataFlowElements().isEmpty() &&
							finding.getDataFlowElements().get(0) != null) {
					location = finding.getDataFlowElements().get(0).getSourceFileName();
				}
				
			} else {
				if (finding.getSurfaceLocation() != null &&
						finding.getSurfaceLocation().getPath() != null) {
					location = finding.getSurfaceLocation().getPath();
				}
			}
		}
		
		return location;
	}
	
	private String cleanStaticUrlPath(String urlPath) {
		String modifiedPath = standardizeSlashes(urlPath);
		
		for (String ending : getSuffixVals()) {
			if (modifiedPath.endsWith(ending)) {
				// remove the . and the extension
				modifiedPath = modifiedPath.substring(0, modifiedPath.length() - (ending.length() + 1));
			}
		}
		
		return modifiedPath;
	}
	
	private String standardizeSlashes(String input) {
		return input.replace('\\', '/');
	}
	
	/**
	 * Returns -1 for not found and otherwise the index to substring.
	 * TODO make this unnecessary
	 */
	private int containsIgnoreCase(String string, String test) {
		if (string == null || test == null) {
			return -1;
		}
		
		String lowerString = string.toLowerCase();
		String lowerTest = test.toLowerCase();
		
		int index = lowerString.indexOf(lowerTest);
		
		if (index != -1) {
			index += lowerTest.length();
		}
		
		return index;
	}
	
	protected final String getFileNameWithSourceCodeDefault(Finding finding) {
		File resultFile = getFileWithSourceCodeDefault(finding);
		
		String projectDirectoryPath = filePathRoot;
		if (projectDirectoryPath == null && projectDirectory != null) {
			projectDirectoryPath = projectDirectory.getDirectoryPath();
		}
		
		return FilePathUtils.getRelativePath(resultFile, projectDirectoryPath);
	}
	
	protected final File getFileWithSourceCodeDefault(Finding finding) {
		File returnFile = null;
		
		if (finding != null && projectDirectory != null) {
			String path = getLocationInformation(finding);
			if (path != null) {
				returnFile = projectDirectory.findFile(path);
			}
		}
		
		return returnFile;
	}
}
