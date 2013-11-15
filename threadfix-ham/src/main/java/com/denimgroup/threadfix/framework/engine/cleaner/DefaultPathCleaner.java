package com.denimgroup.threadfix.framework.engine.cleaner;

import java.util.List;

import org.jetbrains.annotations.NotNull;

import com.denimgroup.threadfix.framework.engine.partial.PartialMapping;
import com.denimgroup.threadfix.framework.util.CommonPathFinder;
import org.jetbrains.annotations.Nullable;

public class DefaultPathCleaner implements PathCleaner {

	protected final String staticRoot, dynamicRoot;
	
	public DefaultPathCleaner(String staticRoot, String dynamicRoot) {
		this.staticRoot  = staticRoot;
		this.dynamicRoot = dynamicRoot;
	}
	
	public DefaultPathCleaner(List<PartialMapping> partialMappings){
		this(CommonPathFinder.findOrParseProjectRoot(partialMappings),
				CommonPathFinder.findOrParseUrlPath(partialMappings));
	}

	@Override
	public String cleanStaticPath(@NotNull String filePath) {
		String cleanedPath = filePath;
		
		if (staticRoot != null && cleanedPath.startsWith(staticRoot)) {
			cleanedPath = cleanedPath.substring(staticRoot.length());
		}
		
		if (cleanedPath.contains("\\")) {
			if (cleanedPath.indexOf("\\") != 0) {
				cleanedPath = "\\" + cleanedPath;
			}
		} else if (cleanedPath.indexOf("/") != 0) {
			cleanedPath = "/" + cleanedPath;
		}
		
		return cleanedPath;
	}

	@Override
	public String cleanDynamicPath(@NotNull String urlPath) {
		String cleanedPath = urlPath;
		
		if (dynamicRoot != null && cleanedPath.startsWith(dynamicRoot)) {
			cleanedPath = cleanedPath.substring(dynamicRoot.length());
		}
		
		if (cleanedPath.contains("\\")) {
            cleanedPath = cleanedPath.replace('\\', '/');
		}
		
		if (cleanedPath.indexOf("/") != 0) {
			cleanedPath = "/" + cleanedPath;
		}
		
		return cleanedPath;
	}

    @Nullable
    @Override
    public String getDynamicPathFromStaticPath(@NotNull String filePath) {
        return filePath;
    }

    @Override
	public String getDynamicRoot() {
		return dynamicRoot;
	}

	@Override
	public String getStaticRoot() {
		return staticRoot;
	}
	
	@NotNull
    @Override
	public String toString() {
		return "[PathCleaner dynamicRoot=" + dynamicRoot + ", staticRoot=" + staticRoot + "]";
	}

}
