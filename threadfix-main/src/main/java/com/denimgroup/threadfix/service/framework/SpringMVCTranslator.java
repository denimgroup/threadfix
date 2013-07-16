package com.denimgroup.threadfix.service.framework;

import java.util.HashMap;
import java.util.Map;

import com.denimgroup.threadfix.data.entities.Finding;
import com.denimgroup.threadfix.data.entities.Scan;
import com.denimgroup.threadfix.service.merge.FrameworkType;
import com.denimgroup.threadfix.service.merge.ScanMergeConfiguration;
import com.denimgroup.threadfix.service.merge.SourceCodeAccessLevel;

public class SpringMVCTranslator extends AbstractPathUrlTranslator {
	
	public static final String GENERIC_INT_SEGMENT = "{id}";
	
	private Map<String, String> mappings = new HashMap<>();

	public SpringMVCTranslator(ScanMergeConfiguration scanMergeConfiguration, Scan scan) {
		super(scanMergeConfiguration, scan);
		
		log.info("Using Spring MVC URL - Path translator.");
		
		SourceCodeAccessLevel accessLevel = scanMergeConfiguration.getSourceCodeAccessLevel();
		
		switch (accessLevel) {
			case FULL:    buildMappingsFromFullSource();    break;
			case PARTIAL: buildMappingsFromPartialSource(); break;
			default: break; // TODO try to guess some mappings based on numeric URL segments
		}
	}

	private void buildMappingsFromPartialSource() {
		log.info("Attempting to build Spring mappings from partial source.");
		
		if (scan != null && scan.isStatic()) {
			addStaticMappings(scan);
		}
		
		// TODO get access to the application so we can do this
		// TODO also cache types used for each scan
//		if (application != null && application.getScans() != null) {
//			for (Scan applicationScan : application.getScans()) {
//				addStaticMappings(applicationScan);
//			}
//		}
	}
	
	// this implementation is for partial source access
	// TODO implement for full source access
	private void addStaticMappings(Scan scan) {
		if (scan != null && scan.getFindings() != null) {
			for (Finding finding : scan.getFindings()) {
				if (finding != null && finding.getStaticPathInformation() != null &&
						finding.getStaticPathInformation().guessFrameworkType() == FrameworkType.SPRING_MVC) {
					String standardizedUrl = 
							getStandardizedUrlStatic(finding.getStaticPathInformation().getValue());
					
					// TODO look into whether or not we need to extract information from data flows
					mappings.put(standardizedUrl, finding.getSourceFileLocation());
				}
			}
		}
	}
	
	// requires full source access
	private void addDynamicMappings(Scan scan) {
		if (scan != null && scan.getFindings() != null) {
			for (Finding finding : scan.getFindings()) {
				if (finding != null && finding.getSurfaceLocation() != null &&
						finding.getSurfaceLocation().getPath() != null) {
					String standardizedUrl = 
							getStandardizedUrlDynamic(finding.getSurfaceLocation().getPath());
					
					// TODO utilize source to match this better
					// probably need to scan for @Controller annotations and extract mappings that way
					mappings.put(standardizedUrl, "???");
				}
			}
		}
	}
	
	// has a templated portion signifying a variable
	private String getStandardizedUrlStatic(String url) {
		return getStandardizedUrl(url, "^\\{.*\\}$"); 
	}
	
	// has an integer url segment which is probably a REST-style parameter
	private String getStandardizedUrlDynamic(String url) {
		return getStandardizedUrl(url, "^[0-9]+$"); 
	}
	
	private String getStandardizedUrl(String url, String segmentRegexToRemove) {
		String standardizedUrl = url;
		
		if (url != null && url.contains("/")) {
			String[] parts = url.split("/");
			
			StringBuilder builder = new StringBuilder();
			for (String part : parts) {
				if (part != null && !part.isEmpty()) {
					builder.append("/");
					if (part.matches(segmentRegexToRemove)) { 
						builder.append(GENERIC_INT_SEGMENT);
					} else {
						builder.append(part);
					}
				}
			}
			standardizedUrl = builder.toString();
		}
		
		return standardizedUrl;
	}

	private void buildMappingsFromFullSource() {
		// TODO Auto-generated method stub
		log.info("Called Spring's unimplemented buildMappingsFromFullSource method");
		addDynamicMappings(scan);
	}

	// TODO utilize source code and find a common root, similar to DefaultTranslator
	@Override
	public String getFileName(Finding finding) {
		
		String fileName = null;
		
		if (finding.getIsStatic()) {
			fileName = finding.getSourceFileLocation();
		} else {
			String urlPathGuess = getUrlPath(finding);
			
			if (urlPathGuess != null && mappings.containsKey(urlPathGuess)) {
				fileName = mappings.get(urlPathGuess);
			}
		}
		
		return fileName;
	}

	@Override
	public String getUrlPath(Finding finding) {
		String urlPath = null;
		
		if (finding != null) {
			if (finding.getIsStatic()) {
				if (finding.getStaticPathInformation() != null &&
						finding.getStaticPathInformation().guessFrameworkType() == FrameworkType.SPRING_MVC) {
					urlPath = getStandardizedUrlStatic(finding.getStaticPathInformation().getValue());
				}
			} else {
				if (finding.getSurfaceLocation() != null) {
					urlPath = getStandardizedUrlDynamic(finding.getSurfaceLocation().getPath());
				}
			}
		}

		return urlPath;
	}
	
}
