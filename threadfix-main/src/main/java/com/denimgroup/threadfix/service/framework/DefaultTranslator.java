package com.denimgroup.threadfix.service.framework;

import java.util.ArrayList;
import java.util.List;

import com.denimgroup.threadfix.data.entities.DataFlowElement;
import com.denimgroup.threadfix.data.entities.Finding;
import com.denimgroup.threadfix.data.entities.Scan;
import com.denimgroup.threadfix.service.SanitizedLogger;
import com.denimgroup.threadfix.service.merge.ScanMergeConfiguration;

public class DefaultTranslator extends AbstractPathUrlTranslator {

	private String filePathRoot, urlPathRoot;
	
	private final SanitizedLogger log = new SanitizedLogger("DefaultTranslator");

	private static final String[] SUFFIX_VALS = { "aspx", "asp", "jsp", "php", "html", "htm",
		"java", "cs", "config", "js", "cgi", "ascx" };
	
	public DefaultTranslator(ScanMergeConfiguration scanMergeConfiguration,
			Scan scan) {
		super(scanMergeConfiguration, scan);

		filePathRoot = findOrParseProjectRoot(scan);
		urlPathRoot = findOrParseUrlPath(scan);
		scan.setFilePathRoot(filePathRoot);
		scan.setUrlPathRoot(urlPathRoot);
		
		log.info("Using default URL - Path translator.");
		log.info("Calculated filesystem root: " + filePathRoot);
		log.info("Calculated url path root: " + urlPathRoot);
	}

	@Override
	public String getFileName(Finding finding) {
		String fileName = getLocationInformation(finding);
		
		int index = containsIgnoreCase(fileName, filePathRoot);
			
		if (index != -1) {
			fileName = fileName.substring(index);
		}
			
		return fileName;
	}

	@Override
	public String getUrlPath(Finding finding) {
		String urlPath = getLocationInformation(finding);
		
		int index = containsIgnoreCase(urlPath, urlPathRoot);
		
		if (index != -1) {
			urlPath = urlPath.substring(index);
		}
		
		if (finding.getIsStatic()) {
			urlPath = cleanStaticUrlPath(urlPath);
		}
			
		return urlPath;
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
	
	private String cleanStaticUrlPath(String urlPath) {
		String modifiedPath = urlPath;
		if (urlPath.indexOf('\\') != -1) {
			modifiedPath = modifiedPath.replace('\\', '/');
		}
		
		for (String ending : SUFFIX_VALS) {
			if (modifiedPath.endsWith(ending)) {
				// remove the . and the extension
				modifiedPath = modifiedPath.substring(0, modifiedPath.length() - (ending.length() + 1));
			}
		}
		
		return modifiedPath;
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

	public static String findOrParseProjectRoot(Scan scan) {
		return parseRoot(getFilePaths(scan));
	}

	public static String findOrParseUrlPath(Scan scan) {
		return parseRoot(getUrlPaths(scan));
	}

	static private List<String> getFilePaths(Scan scan) {
		if (scan == null || scan.getFindings() == null
				|| scan.getFindings().isEmpty()) {
			return null;
		}

		List<String> returnString = new ArrayList<>();

		for (Finding finding : scan.getFindings()) {
			if (finding.getIsStatic()) {
				List<DataFlowElement> dataFlowElements = finding.getDataFlowElements();
				if (dataFlowElements == null || dataFlowElements.size() == 0)
					continue;

				if (dataFlowElements.get(0) != null
						&& dataFlowElements.get(0).getSourceFileName() != null) {
					returnString.add(dataFlowElements.get(0)
							.getSourceFileName());
				}
			}
		}

		return returnString;
	}

	static private List<String> getUrlPaths(Scan scan) {
		if (scan == null || scan.getFindings() == null
				|| scan.getFindings().isEmpty()) {
			return null;
		}

		List<String> returnStrings = new ArrayList<>();

		for (Finding finding : scan.getFindings()) {
			if (finding != null && finding.getSurfaceLocation() != null
					&& finding.getSurfaceLocation().getPath() != null) {
				returnStrings.add(finding.getSurfaceLocation().getPath());
			}
		}

		return returnStrings;
	}

	static private String parseRoot(List<String> items) {
		if (items == null || items.isEmpty())
			return null;

		String commonPrefix = null;

		for (String string : items) {
			if (commonPrefix == null) {
				commonPrefix = string;
			} else {
				commonPrefix = findCommonPrefix(string, commonPrefix);
			}
		}

		if (commonPrefix != null && !commonPrefix.equals("")) {
			if (commonPrefix.contains("/")) {
				while (commonPrefix.endsWith("/")) {
					commonPrefix = commonPrefix.substring(0,
							commonPrefix.length() - 1);
				}

				if (commonPrefix.contains("/")) {
					commonPrefix = commonPrefix.substring(
							commonPrefix.lastIndexOf("/") + 1).replace("/", "");
				}
			}
		}

		return commonPrefix;
	}

	static private String findCommonPrefix(String newString, String oldString) {
		if (newString == null || oldString == null)
			return "";
		if (newString.toLowerCase().contains(oldString.toLowerCase()))
			return oldString;

		String newLower = newString.replace("\\", "/").toLowerCase();
		String oldLower = oldString.replace("\\", "/").toLowerCase();

		String returnString = "";

		for (String string : oldLower.split("/")) {
			String tempString = returnString.concat(string + "/");
			if (newLower.startsWith(tempString)) {
				returnString = tempString;
			} else {
				break;
			}
		}

		return oldString.replace("\\", "/").substring(0, returnString.length());
	}

}
