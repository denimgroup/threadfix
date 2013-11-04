package com.denimgroup.threadfix.framework.engine;

import java.util.List;

import com.denimgroup.threadfix.framework.beans.PartialMapping;
import com.denimgroup.threadfix.framework.beans.PathCleaner;
import com.denimgroup.threadfix.framework.util.CommonPathFinder;

public class DefaultPathCleaner implements PathCleaner {
	
	private final String staticRoot, dynamicRoot;
	
	public DefaultPathCleaner(String staticRoot, String dynamicRoot) {
		this.staticRoot  = staticRoot;
		this.dynamicRoot = dynamicRoot;
	}
	
	public DefaultPathCleaner(List<PartialMapping> partialMappings){
		this(CommonPathFinder.findOrParseProjectRoot(partialMappings),
				CommonPathFinder.findOrParseUrlPath(partialMappings));
	}

	@Override
	public String cleanStaticPath(String filePath) {
		String cleanedPath = filePath;
		
		if (staticRoot != null && cleanedPath.startsWith(staticRoot)) {
			cleanedPath = cleanedPath.substring(staticRoot.length());
		}
		
		return cleanedPath;
	}

	@Override
	public String cleanDynamicPath(String urlPath) {
		String cleanedPath = urlPath;
		
		if (dynamicRoot != null && cleanedPath.startsWith(dynamicRoot)) {
			cleanedPath = cleanedPath.substring(dynamicRoot.length());
		}
		
		return cleanedPath;
	}

	@Override
	public String getDynamicRoot() {
		return dynamicRoot;
	}

	@Override
	public String getStaticRoot() {
		return staticRoot;
	}

}
