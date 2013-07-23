package com.denimgroup.threadfix.service.framework;

import java.io.File;
import java.util.Arrays;

import com.denimgroup.threadfix.data.entities.Finding;
import com.denimgroup.threadfix.data.entities.Scan;
import com.denimgroup.threadfix.service.SanitizedLogger;
import com.denimgroup.threadfix.service.merge.ScanMergeConfiguration;

public abstract class AbstractPathUrlTranslator implements PathUrlTranslator {
	
	protected String filePathRoot, urlPathRoot;
	
	private static Iterable<String> SUFFIXES = Arrays.asList("aspx", "asp", "jsp", "php", "html", "htm",
        "java", "cs", "config", "js", "cgi", "ascx");
	
	protected final ServletMappings mappings;
	protected final File workTree;
	protected final String applicationRoot;
	protected final ScanMergeConfiguration scanMergeConfiguration;
	protected final Scan scan;
	
	protected final SanitizedLogger log = new SanitizedLogger(this.getClass());
	
	/**
	 * Throws IllegalArgumentException if passed null parameters.
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
	
	/**
	 * This method is useful to override for g
	 * @return
	 */
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
					(finding.getDataFlowElements() != null && 
							!finding.getDataFlowElements().isEmpty() &&
							finding.getDataFlowElements().get(0) != null)) {
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
	
}
